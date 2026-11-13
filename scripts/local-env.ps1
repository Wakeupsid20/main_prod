function Initialize-VeilLocalEnvironment {
 param([string]$ProjectRoot, [string]$KeyDirectory)
 $envFile = Join-Path $ProjectRoot '.env'
 if (!(Test-Path -LiteralPath $envFile)) {
  Add-Type -AssemblyName System.Security
  $keyFile = Join-Path $KeyDirectory 'data-key.dpapi'
  if (Test-Path -LiteralPath $keyFile) {
   # Preserve the existing key so previously encrypted registry data remains readable.
   $dataKey = [System.Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($keyFile), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
  } else {
   if (Test-Path -LiteralPath (Join-Path $ProjectRoot 'data/registry.db')) { throw 'Existing registry found without its key. Restore the original data key before starting.' }
   $dataKey = New-Object byte[] 32
   $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
   try { $rng.GetBytes($dataKey) } finally { $rng.Dispose() }
   New-Item -ItemType Directory -Path $KeyDirectory -Force | Out-Null
   [IO.File]::WriteAllBytes($keyFile, [System.Security.Cryptography.ProtectedData]::Protect($dataKey, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
  }
  $tokens = @()
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { foreach ($i in 1..2) { $bytes = New-Object byte[] 32; $rng.GetBytes($bytes); $tokens += [Convert]::ToBase64String($bytes) } } finally { $rng.Dispose() }
  $lines = @('# Private local configuration. Never commit this file.', '# Keep ZKP_DATA_KEY unchanged while using this registry.', 'ZKP_CLOUD=0', ('ZKP_ADMIN_TOKEN=' + $tokens[0]), ('ZKP_WALLET_TOKEN=' + $tokens[1]), ('ZKP_DATA_KEY=' + [Convert]::ToBase64String($dataKey)))
  [IO.File]::WriteAllLines($envFile, $lines, (New-Object System.Text.UTF8Encoding($false)))
 }
 $allowed = @('ZKP_CLOUD','ZKP_ADMIN_TOKEN','ZKP_WALLET_TOKEN','ZKP_DATA_KEY','ZKP_DB','ZKP_WALLET_DIR','ZKP_DEV_ORIGIN')
 $values = @{}
 foreach ($line in [IO.File]::ReadAllLines($envFile)) {
  if (!$line.Trim() -or $line.TrimStart().StartsWith('#')) { continue }
  if ($line -notmatch '^\s*([A-Z_][A-Z0-9_]*)=(.*)$') { throw 'Invalid .env entry. Use KEY=value without quotes or shell expressions.' }
  $name = $Matches[1]; $value = $Matches[2].Trim()
  if ($name -notin $allowed -or $values.ContainsKey($name)) { throw 'Unknown or duplicate .env setting.' }
  $values[$name] = $value
 }
 if ($values['ZKP_CLOUD'] -ne '0') { throw 'start.ps1 requires a local .env with ZKP_CLOUD=0. Use Render Environment settings for cloud deployment.' }
 foreach ($name in 'ZKP_ADMIN_TOKEN','ZKP_WALLET_TOKEN') { if ($values[$name].Length -lt 32) { throw ('Missing or invalid ' + $name) } }
 try { $validKey = [Convert]::FromBase64String($values['ZKP_DATA_KEY']) } catch { throw 'Invalid ZKP_DATA_KEY encoding.' }
 if ($validKey.Length -ne 32) { throw 'ZKP_DATA_KEY must encode 32 bytes.' }
 foreach ($name in $values.Keys) { [Environment]::SetEnvironmentVariable($name, $values[$name], 'Process') }
}
