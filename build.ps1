# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if (!(Test-Path -LiteralPath $taskCompiler)) { throw '.NET Framework 4.8 with its x64 C# compiler is required.' }
$taskSource = Join-Path $PSScriptRoot 'src/chiptool.cs'
$taskDriver = Join-Path $PSScriptRoot 'src/WinRing0x64.sys'
$taskMemoryDriver = Join-Path $PSScriptRoot 'src/inpoutx64.sys'
$taskLicense = Join-Path $PSScriptRoot 'LICENSE'
$taskNotices = Join-Path $PSScriptRoot 'THIRD_PARTY_NOTICES.txt'
$taskOutput = Join-Path $PSScriptRoot 'dist'
New-Item -ItemType Directory -Force $taskOutput | Out-Null
$taskCandidate = Join-Path $taskOutput ('.chiptool-' + [Guid]::NewGuid().ToString('N') + '.exe')
$taskExe = Join-Path $taskOutput 'chiptool.exe'

try {
    & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /debug- /warn:4 /warnaserror+ "/out:$taskCandidate" /reference:System.Core.dll "/resource:$taskDriver,chiptool.winring" "/resource:$taskMemoryDriver,chiptool.inpout" "/resource:$taskLicense,chiptool.license" "/resource:$taskNotices,chiptool.notices" $taskSource
    if ($LASTEXITCODE -ne 0) { throw "Compilation failed with exit code $LASTEXITCODE." }
    Move-Item -LiteralPath $taskCandidate -Destination $taskExe -Force
}
finally {
    if (Test-Path -LiteralPath $taskCandidate) { Remove-Item -LiteralPath $taskCandidate -Force }
}
Write-Host "Built $taskExe"
