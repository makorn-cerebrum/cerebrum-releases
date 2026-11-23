# Cerebrum customer installer. Put your licence file (*.license.json from Cerebrum) next to this script, then run
# "Install Cerebrum.cmd". It installs every app your licence includes and checks for updates every day.
$ErrorActionPreference = "Stop"
$Base   = "https://raw.githubusercontent.com/makorn-cerebrum/cerebrum-releases/main"
$Root   = Join-Path $env:LOCALAPPDATA "Cerebrum"
$PyDir  = Join-Path $Root "python"
$Tools  = Join-Path $Root "release"
New-Item -ItemType Directory -Force -Path $Root, $Tools | Out-Null

$lic = Get-ChildItem -Path $PSScriptRoot -Filter *.license.json | Select-Object -First 1
if (-not $lic) { throw "Put your Cerebrum licence file (.license.json) in this folder and run again." }
Copy-Item $lic.FullName (Join-Path $Root "cerebrum.license.json") -Force

if (-not (Test-Path (Join-Path $PyDir "python.exe"))) {
  $url = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip"
  $sha = "4ACBED6DD1C744B0376E3B1CF57CE906F9DC9E95E68824584C8099A63025A3C3"
  $tmp = Join-Path $env:TEMP "cerebrum-python.zip"
  Write-Host "Getting Python 3.12 (official, about 11 MB)..."
  Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
  if ((Get-FileHash $tmp -Algorithm SHA256).Hash -ne $sha) { Remove-Item $tmp; throw "Python download failed its integrity check." }
  Expand-Archive -Path $tmp -DestinationPath $PyDir -Force; Remove-Item $tmp
}
foreach ($f in "cerebrum_release.py", "cerebrum_crypto.py") {
  Invoke-WebRequest -Uri "$Base/$f" -OutFile (Join-Path $Tools $f) -UseBasicParsing
}
$py = Join-Path $PyDir "python.exe"
$apps = (Get-Content $lic.FullName -Raw | ConvertFrom-Json).apps
if ($apps -contains "*") { $apps = @("brain") }
$targets = @{ "brain" = (Join-Path ([Environment]::GetFolderPath("MyDocuments")) "Cerebrum Brain") }

foreach ($app in $apps) {
  $dir = $targets[$app]; if (-not $dir) { $dir = Join-Path $Root $app }
  & $py (Join-Path $Tools "cerebrum_release.py") install --license (Join-Path $Root "cerebrum.license.json") --app $app --dir $dir
  if ($LASTEXITCODE -ne 0) { throw "Could not install $app." }
  $appPy = Join-Path $dir "_system\python"
  if (-not (Test-Path (Join-Path $appPy "python.exe"))) { Copy-Item $PyDir $appPy -Recurse -Force }
  $appInstall = Join-Path $dir "_system\install.ps1"
  if (Test-Path $appInstall) { & powershell -NoProfile -ExecutionPolicy Bypass -File $appInstall }
  # daily update check for this app
  $act = New-ScheduledTaskAction -Execute $py -Argument "`"$(Join-Path $Tools 'cerebrum_release.py')`" update --dir `"$dir`""
  $trg = New-ScheduledTaskTrigger -Daily -At 9:15am
  Register-ScheduledTask -TaskName "Cerebrum update ($app)" -Action $act -Trigger $trg -Description "Gets signed Cerebrum updates" -Force | Out-Null
}
Write-Host ""
Write-Host "Done. Your Cerebrum apps are installed and update themselves every day." -ForegroundColor Green
