$ErrorActionPreference='Stop'
Set-Location $PSScriptRoot
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {throw 'Python install failed'}
& npm.cmd ci
if ($LASTEXITCODE -ne 0) {throw 'Node install failed'}
& npm.cmd run setup:zk
if ($LASTEXITCODE -ne 0) {throw 'ZKP setup failed'}
& npm.cmd run build
if ($LASTEXITCODE -ne 0) {throw 'Build failed'}
