# eXe installer (Windows).
#
#   irm https://exe.ntnl.io/install.ps1 | iex
#
#   $env:EXE_VERSION = "v0.5.0"    pin a version (fetched from GitHub)
#   $env:EXE_INSTALL_DIR = "..."   choose where the binary lands
#
# It installs a binary and nothing else: no task, no configuration. Run `exe`
# afterwards to set the machine up.
$ErrorActionPreference = "Stop"

$base = if ($env:EXE_BASE) { $env:EXE_BASE } else { "https://exe.ntnl.io" }
$repo = if ($env:EXE_REPO) { $env:EXE_REPO } else { "zccz14/eXe" }
$asset = "exe-x86_64-pc-windows-msvc.zip"

$dir = if ($env:EXE_INSTALL_DIR) { $env:EXE_INSTALL_DIR } else { "$env:LOCALAPPDATA\exe" }

if ($env:EXE_VERSION) {
  $url = "https://github.com/$repo/releases/download/$($env:EXE_VERSION)/$asset"
} else {
  $url = "$base/download/$asset"
}

$tmp = Join-Path $env:TEMP ("exe-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "exe: $url"
  $zip = Join-Path $tmp $asset
  Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "$url.sha256" -OutFile "$zip.sha256"
  } catch {
    throw "no checksum published for $asset — refusing to install"
  }
  $expected = ((Get-Content "$zip.sha256" -Raw) -split '\s+')[0].ToLower()
  $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { throw "checksum mismatch: the download is corrupt or was modified in transit" }

  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Copy-Item (Join-Path $tmp "exe.exe") (Join-Path $dir "exe.exe") -Force
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$exe = Join-Path $dir "exe.exe"
Write-Host "exe: installed $exe"
$machine = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($machine -notlike "*$dir*") {
  [Environment]::SetEnvironmentVariable("PATH", "$machine;$dir", "User")
  Write-Host "exe: added $dir to your user PATH (open a new terminal)"
}

Write-Host ""
Write-Host "Next, on this machine:"
Write-Host "  exe                    set it up as a device: key, background task, proof"
Write-Host "  exe --trust <address>  the same, and allow calls from that caller"
Write-Host "  exe status             what the relay sees, and where the log is"
