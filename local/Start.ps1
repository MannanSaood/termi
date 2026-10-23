param(
    [Parameter(Mandatory=$true)][string]$Repository,
    [Parameter(Mandatory=$true)][string]$Keyring,
    [string]$Bind = '127.0.0.1',
    [ValidateRange(1024,65535)][int]$Port = 8765
)
$ErrorActionPreference = 'Stop'
$runtime = Join-Path $PSScriptRoot 'runtime'
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$pidFile = Join-Path $runtime 'server.json'
if (Test-Path -LiteralPath $pidFile) {
    $previous = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
    if (Get-Process -Id $previous.pid -ErrorAction SilentlyContinue) {
        throw 'Recorded server process exists. Use local/Stop.ps1 before starting another.'
    }
}
$repositoryPath = (Resolve-Path -LiteralPath $Repository).Path
$keyPath = (Resolve-Path -LiteralPath $Keyring).Path
$reportName = 'verified-' + [Guid]::NewGuid().ToString('N') + '.json'
$report = Join-Path $runtime $reportName
$builder = 'ghcr.io/termux/package-builder@sha256:44999857244619e25bc8e3427904a16d36cc0c0e087704af039e5bdf94814ac9'
& docker run --rm --network none --cpus 2 --memory 1g --pids-limit 128 --security-opt no-new-privileges `
    --mount "type=bind,source=$PSScriptRoot,target=/work,readonly" `
    --mount "type=bind,source=$repositoryPath,target=/repository,readonly" `
    --mount "type=bind,source=$keyPath,target=/trust/repository-keyring.gpg,readonly" `
    --mount "type=bind,source=$runtime,target=/results" `
    $builder python3 /work/verify.py --root /repository --keyring /trust/repository-keyring.gpg --output "/results/$reportName"
if ($LASTEXITCODE -ne 0) { throw 'Repository verification failed; server was not started.' }
$pin = (Get-FileHash -LiteralPath $report -Algorithm SHA256).Hash.ToLowerInvariant()
$python = (Get-Command pythonw.exe -ErrorAction Stop).Source
$serverScript = Join-Path $PSScriptRoot 'serve.py'
$arguments = @($serverScript, '--root', $repositoryPath, '--verification', $report, '--verification-sha256', $pin, '--bind', $Bind, '--port', "$Port")
# Start-Process joins its argument array. Quote each literal path/value once.
$quoted = ($arguments | ForEach-Object { if ($_ -match '["\r\n]') { throw 'Invalid command argument' }; '"' + $_ + '"' }) -join ' '
$process = Start-Process -FilePath $python -ArgumentList $quoted -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $runtime 'server.stdout.log') -RedirectStandardError (Join-Path $runtime 'server.stderr.log')
@{ pid=$process.Id; script=$serverScript; root=$repositoryPath; bind=$Bind; port=$Port; verification=$report; sha256=$pin } |
    ConvertTo-Json | Set-Content -LiteralPath $pidFile
$ready = $false
for ($attempt=0; $attempt -lt 30; $attempt++) {
    try {
        $state = Invoke-RestMethod -Uri "http://${Bind}:$Port/healthz" -TimeoutSec 1
        $ready = $true
        break
    } catch {
        if ($process.HasExited) { throw 'Server exited; inspect local/runtime/server.stderr.log.' }
        Start-Sleep -Milliseconds 200
    }
}
if (-not $ready) { throw 'Server did not become reachable; inspect the server log and firewall.' }
Write-Output "Serving $($state.packages) reviewed packages at http://${Bind}:$Port/apt/main/"
Write-Output 'Full catalog is still building. No app source settings have been changed.'
