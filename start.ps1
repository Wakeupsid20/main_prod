param([switch]$SkipBuild, [string]$KeyDirectory = (Join-Path $env:LOCALAPPDATA 'VeilZKP'))
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
. (Join-Path $PSScriptRoot 'scripts/local-env.ps1')
foreach ($port in 8000,8001) {
 $probe=New-Object System.Net.Sockets.TcpClient
 $occupied=$false
 try { $task=$probe.ConnectAsync('127.0.0.1',$port); $null=$task.Wait(500); $occupied=$probe.Connected } catch {} finally { $probe.Dispose() }
 if ($occupied) { throw "Port $port is already in use. Stop the prior demo services first." }
}
Initialize-VeilLocalEnvironment -ProjectRoot $PSScriptRoot -KeyDirectory $KeyDirectory
$python=Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (!(Test-Path -LiteralPath $python)) { throw 'Run setup.ps1 first.' }
if (!$SkipBuild) { & npm.cmd run build; if ($LASTEXITCODE -ne 0) {throw 'Frontend build failed'} }
if (!(Test-Path -LiteralPath 'build\session\final.zkey')) {throw 'Run npm.cmd run setup:zk first.'}
Write-Host 'Secrets loaded privately from .env. Open http://127.0.0.1:8000. Ctrl+C stops both services.'
$wallet=Start-Process -FilePath $python -ArgumentList '-m','uvicorn','backend.wallet:app','--host','127.0.0.1','--port','8001','--no-access-log' -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
try { & $python -m uvicorn backend.api:app --host 127.0.0.1 --port 8000 --no-access-log }
finally { Stop-Process -Id $wallet.Id -ErrorAction SilentlyContinue; Remove-Item Env:ZKP_ADMIN_TOKEN,Env:ZKP_WALLET_TOKEN,Env:ZKP_DATA_KEY -ErrorAction SilentlyContinue }

