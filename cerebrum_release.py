#!/usr/bin/env python3
"""Cerebrum releases: sealed app packages on a public GitHub repo, for licensed customers only.

Publisher (Cerebrum's own machines):
  python cerebrum_release.py keygen
  python cerebrum_release.py customer --name "Acme Co" --plan business --apps brain,store --expires 2027-12-31
  python cerebrum_release.py publish --app brain --version 1.0.1 --zip path\\to\\package.zip --repo path\\to\\cerebrum-releases [--notes "..."] [--push]

Customer workstation (the bootstrap runs this):
  python cerebrum_release.py install --license my.license.json --app brain --dir "C:\\Cerebrum\\Brain"
  python cerebrum_release.py update  --dir "C:\\Cerebrum\\Brain"

How it protects the apps
  * The code repos stay private. The public releases repo only holds packages sealed with AES-256-CTR + HMAC-SHA256.
  * Each version gets a random content key, wrapped separately for every licence allowed to have it.
    A licence's secret is only in the licence file Cerebrum gives that customer.
  * The index, every licence and every package are signed with Cerebrum's RSA-3072 key. Workstations pin that
    key on first install and refuse anything not signed by it.
  * Customer IDs in the public index are random; names and plans stay in Cerebrum's private customer list.
"""
import argparse
import datetime as dt
import hashlib
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cerebrum_crypto as cc  # noqa: E402

DEFAULT_RELEASES = "https://raw.githubusercontent.com/makorn-cerebrum/cerebrum-releases/main"
PUBLISHER_HOME = Path(os.environ.get("CEREBRUM_PUBLISHER_HOME", Path.home() / ".cerebrum" / "publisher"))
# Files a package may never overwrite on a customer machine (their own data)
PROTECTED = ("Projects/", "People/", "Countries/", "Interests/", "Daily/", "Memory/", "Conversations/", "Research/",
             "Inbox/", "Wiki/", "_system/settings.json", "_system/security.json", "_system/ai-cache.json",
             "_system/briefing.json", "_system/search-index.json", "_system/brain-data.js", "_system/python/")


def say(*a):
    print(*a, flush=True)


def today():
    return dt.date.today().isoformat()


# ---------------------------------------------------------------- publisher side
def _priv():
    p = PUBLISHER_HOME / "signing-key.json"
    if not p.exists():
        raise SystemExit("No signing key yet. Run: cerebrum_release.py keygen")
    return cc.priv_from_json(json.loads(p.read_text(encoding="utf-8")))


def keygen(force=False):
    PUBLISHER_HOME.mkdir(parents=True, exist_ok=True)
    p = PUBLISHER_HOME / "signing-key.json"
    if p.exists() and not force:
        k = cc.priv_from_json(json.loads(p.read_text(encoding="utf-8")))
        return {"created": False, "key_id": cc.key_id(k), "path": str(p)}
    k = cc.rsa_generate(3072)
    p.write_text(json.dumps(cc.priv_to_json(k)), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    pub = {**cc.pub_to_json(k), "key_id": cc.key_id(k), "name": "Cerebrum", "created": today()}
    (PUBLISHER_HOME / "publisher.json").write_text(json.dumps(pub, indent=2), encoding="utf-8")
    return {"created": True, "key_id": pub["key_id"], "path": str(p)}


def public_doc():
    return json.loads((PUBLISHER_HOME / "publisher.json").read_text(encoding="utf-8"))


def customers():
    p = PUBLISHER_HOME / "customers.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def add_customer(name, plan, apps, expires):
    priv = _priv()
    lic_id = "c-" + secrets.token_hex(6)
    secret = secrets.token_bytes(32)
    lic = cc.sign_doc(priv, {"license_id": lic_id, "customer": name, "plan": plan, "apps": apps, "expires": expires,
                              "issued": today(), "publisher": cc.key_id(priv), "secret": cc.b64(secret)})
    cs = customers()
    cs.append({k: lic[k] for k in ("license_id", "customer", "plan", "apps", "expires", "issued", "secret")})
    (PUBLISHER_HOME / "customers.json").write_text(json.dumps(cs, indent=2, ensure_ascii=False), encoding="utf-8")
    out = PUBLISHER_HOME / "licenses"
    out.mkdir(exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in name)[:40]
    f = out / f"{safe}-{lic_id}.license.json"
    f.write_text(json.dumps(lic, indent=2, ensure_ascii=False), encoding="utf-8")
    return lic, f


def _allowed(c, app, on):
    return (app in c["apps"] or "*" in c["apps"]) and c["expires"] >= on


def publish(app, version, package_bytes, repo_dir, notes="", push=False):
    """Seal a package for every licence that may have it, update the signed index, and (optionally) git push."""
    priv = _priv()
    repo = Path(repo_dir)
    (repo / "packages" / app).mkdir(parents=True, exist_ok=True)
    content_key = secrets.token_bytes(32)
    aad = f"{app}:{version}".encode()
    sealed = cc.seal(content_key, package_bytes, aad)
    rel = f"packages/{app}/{app}-{version}.cbpk"
    (repo / rel).write_bytes(sealed)
    keys = {}
    for c in customers():
        if _allowed(c, app, today()):
            keys[c["license_id"]] = cc.b64(cc.seal(cc.unb64(c["secret"]), content_key, f"{aad.decode()}:{c['license_id']}".encode()))
    idx_p = repo / "index.json"
    idx = json.loads(idx_p.read_text(encoding="utf-8")) if idx_p.exists() else {"format": 1, "apps": {}}
    idx.pop("sig", None)
    entry = {"version": version, "file": rel, "sha256": hashlib.sha256(sealed).hexdigest(), "size": len(sealed),
             "published": today(), "notes": notes, "keys": keys}
    app_e = idx["apps"].setdefault(app, {"latest": version, "versions": []})
    app_e["versions"] = [v for v in app_e["versions"] if v["version"] != version] + [entry]
    app_e["latest"] = version
    idx["updated"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    idx["publisher"] = cc.key_id(priv)
    idx_p.write_text(json.dumps(cc.sign_doc(priv, idx), indent=1), encoding="utf-8")
    (repo / "publisher.json").write_text(json.dumps(public_doc(), indent=2), encoding="utf-8")
    here = Path(__file__).resolve().parent
    for f in ("cerebrum_release.py", "cerebrum_crypto.py"):
        shutil.copy2(here / f, repo / f)
    kit = here / "release-kit"
    if kit.exists():
        for f in kit.iterdir():
            if f.is_file():
                shutil.copy2(f, repo / f.name)
    result = {"ok": True, "file": rel, "size": len(sealed), "licences": len(keys)}
    if push:
        def git(*a):
            r = subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)
            return r.returncode, (r.stdout + r.stderr).strip()
        git("add", "-A")
        code, out = git("commit", "-m", f"{app} {version}" + (f": {notes}" if notes else ""))
        if code not in (0, 1):
            return {**result, "push": out}
        code, out = git("push", "origin", "HEAD")
        result["push"] = "pushed to GitHub" if code == 0 else out.splitlines()[0][:200]
    return result


# ---------------------------------------------------------------- customer side
def _fetch(base, rel):
    if base.startswith(("http://", "https://")):
        req = urllib.request.Request(f"{base.rstrip('/')}/{rel}", headers={"User-Agent": "Cerebrum-Release", "Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read()
    return (Path(base) / rel).read_bytes()


def _state_path(install_dir):
    return Path(install_dir) / "_system" / "cerebrum-install.json"


def _pinned_publisher(base, install_dir):
    st = _state_path(install_dir)
    if st.exists():
        s = json.loads(st.read_text(encoding="utf-8"))
        return s["publisher"]
    pub = json.loads(_fetch(base, "publisher.json"))  # first install: trust on first use, then pinned
    return pub


def _check_license(lic, pub, app):
    if not cc.verify_doc(cc.pub_from_json(pub), lic):
        raise SystemExit("This licence file isn't signed by Cerebrum.")
    if lic["expires"] < today():
        raise SystemExit(f"This licence expired on {lic['expires']}. Contact Cerebrum to renew.")
    if app not in lic["apps"] and "*" not in lic["apps"]:
        raise SystemExit(f"This licence doesn't include {app}.")


def _install_zip(data, install_dir):
    dest = Path(install_dir)
    dest.mkdir(parents=True, exist_ok=True)
    n = 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            name = info.filename.replace("\\", "/")
            if info.is_dir() or name.startswith("/") or ".." in name.split("/"):
                continue
            target = dest / name
            if any(name.startswith(p) for p in PROTECTED) and target.exists():
                continue  # never overwrite the customer's own data
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(info))
            n += 1
    return n


def install(license_file, app, install_dir, base=DEFAULT_RELEASES, version=None):
    lic = json.loads(Path(license_file).read_text(encoding="utf-8"))
    pub = _pinned_publisher(base, install_dir)
    _check_license(lic, pub, app)
    idx = json.loads(_fetch(base, "index.json"))
    if not cc.verify_doc(cc.pub_from_json(pub), idx):
        raise SystemExit("The release index isn't signed by Cerebrum. Nothing was installed.")
    a = idx["apps"].get(app)
    if not a:
        raise SystemExit(f"{app} isn't published yet.")
    want = version or a["latest"]
    entry = next((v for v in a["versions"] if v["version"] == want), None)
    if not entry:
        raise SystemExit(f"Version {want} not found.")
    wrapped = entry["keys"].get(lic["license_id"])
    if not wrapped:
        raise SystemExit(f"Version {want} isn't released for this licence yet. Contact Cerebrum.")
    say(f"Downloading {app} {want} ({entry['size'] / 1e6:.1f} MB)…")
    blob = _fetch(base, entry["file"])
    if hashlib.sha256(blob).hexdigest() != entry["sha256"]:
        raise SystemExit("Download damaged (checksum). Try again.")
    aad = f"{app}:{want}"
    key = cc.open_sealed(cc.unb64(lic["secret"]), cc.unb64(wrapped), f"{aad}:{lic['license_id']}".encode())
    data = cc.open_sealed(key, blob, aad.encode())
    n = _install_zip(data, install_dir)
    st = _state_path(install_dir)
    st.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(license_file, st.parent / "cerebrum.license.json") if Path(license_file).resolve() != (st.parent / "cerebrum.license.json").resolve() else None
    st.write_text(json.dumps({"app": app, "version": want, "base": base, "publisher": pub,
                              "installed": dt.datetime.now().isoformat(timespec="seconds")}, indent=2), encoding="utf-8")
    say(f"Installed {app} {want}: {n} files. Your own data was not touched.")
    return {"app": app, "version": want, "files": n}


def update(install_dir, check_only=False):
    st = json.loads(_state_path(install_dir).read_text(encoding="utf-8"))
    lic_f = _state_path(install_dir).parent / "cerebrum.license.json"
    idx = json.loads(_fetch(st["base"], "index.json"))
    if not cc.verify_doc(cc.pub_from_json(st["publisher"]), idx):
        raise SystemExit("The release index isn't signed by Cerebrum. No update.")
    latest = idx["apps"].get(st["app"], {}).get("latest")
    if not latest or latest == st["version"]:
        say(f"{st['app']} {st['version']} is up to date.")
        return {"update": False, "version": st["version"]}
    if check_only:
        say(f"Update available: {st['app']} {latest} (installed {st['version']}).")
        return {"update": True, "latest": latest, "version": st["version"]}
    return install(lic_f, st["app"], install_dir, st["base"], latest)


def main():
    ap = argparse.ArgumentParser(description="Cerebrum releases")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    c = sub.add_parser("customer"); c.add_argument("--name", required=True); c.add_argument("--plan", default="starter")
    c.add_argument("--apps", default="*"); c.add_argument("--expires", required=True)
    p = sub.add_parser("publish"); p.add_argument("--app", required=True); p.add_argument("--version", required=True)
    p.add_argument("--zip", required=True); p.add_argument("--repo", required=True); p.add_argument("--notes", default=""); p.add_argument("--push", action="store_true")
    i = sub.add_parser("install"); i.add_argument("--license", required=True); i.add_argument("--app", required=True)
    i.add_argument("--dir", required=True); i.add_argument("--base", default=DEFAULT_RELEASES); i.add_argument("--version")
    u = sub.add_parser("update"); u.add_argument("--dir", required=True); u.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if a.cmd == "keygen":
        r = keygen(); say(("Created" if r["created"] else "Already have") + f" signing key {r['key_id']} at {r['path']}. Back it up somewhere safe.")
    elif a.cmd == "customer":
        lic, f = add_customer(a.name, a.plan, [x.strip() for x in a.apps.split(",") if x.strip()], a.expires)
        say(f"Licence {lic['license_id']} for {a.name}: {f}\nGive this file to the customer privately.")
    elif a.cmd == "publish":
        say(json.dumps(publish(a.app, a.version, Path(a.zip).read_bytes(), a.repo, a.notes, a.push), indent=2))
    elif a.cmd == "install":
        install(a.license, a.app, a.dir, a.base, a.version)
    elif a.cmd == "update":
        update(a.dir, a.check)


if __name__ == "__main__":
    main()
