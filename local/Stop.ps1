$ErrorActionPreference = 'Stop'
$pidFile = Join-Path $PSScriptRoot 'runtime/server.json'
if (-not (Test-Path -LiteralPath $pidFile)) { Write-Output 'No recorded local server.'; exit 0 }
$state = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
$process = Get-CimInstance Win32_Process -Filter "ProcessId = $($state.pid)"
if ($process) {
    if ($process.Name -ne 'pythonw.exe' -or -not $process.CommandLine.Contains($state.script) -or
        -not $process.CommandLine.Contains($state.verification)) {
        throw 'PID belongs to another process; refusing to stop it.'
    }
    Stop-Process -Id $state.pid
}
Remove-Item -LiteralPath $pidFile
Write-Output 'Termi local server stopped. Repository files unchanged.'
