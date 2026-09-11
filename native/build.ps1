# Builds libfarewell.so (arm64-v8a) with the Android NDK.
# Usage: pwsh -File native/build.ps1 [-Ndk <path>]

param(
    [string]$Ndk = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not $Ndk) {
    $candidates = Get-ChildItem "$env:LOCALAPPDATA\Android\Sdk\ndk" -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending
    if (-not $candidates) { throw "NDK not found; pass -Ndk <path>" }
    $Ndk = $candidates[0].FullName
}

$cc = Join-Path $Ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android31-clang.cmd"
if (-not (Test-Path $cc)) { throw "clang not found: $cc" }

$out = Join-Path $root "build\native"
New-Item -ItemType Directory -Force -Path $out | Out-Null

& $cc -shared -O2 -fPIC -Wall -o (Join-Path $out "libfarewell.so") (Join-Path $root "native\farewell.c") -llog
if ($LASTEXITCODE -ne 0) { throw "clang failed" }

Copy-Item (Join-Path $out "libfarewell.so") (Join-Path $root "app\assets\libfarewell.so") -Force
$size = (Get-Item (Join-Path $out "libfarewell.so")).Length
Write-Output "libfarewell.so built ($size bytes) with $Ndk"
