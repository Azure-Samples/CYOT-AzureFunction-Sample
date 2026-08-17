<#
.SYNOPSIS
    Generates a test RSA keypair ("test certificate") for CYOT JWE decryption and stores the private
    key in Key Vault. The public key is what SAS uses to encrypt encryptedDeliveryContext; the private
    key is what the Function decrypts with (resolved from Key Vault by the JOSE `kid`).

.DESCRIPTION
    RSA-OAEP-256 wraps the AES-256-GCM content key, so SAS needs the PUBLIC key (the cert) and the
    endpoint needs the PRIVATE key. This script:
      1. Generates an RSA-2048 keypair.
      2. Writes both PEMs to scripts/.keys/ (gitignored — private keys never get committed).
      3. Uploads the private key PEM to Key Vault as a secret named after the `kid`.
    Share the printed public key with SAS. Nothing here is a customer secret — the nonce is generated
    per-request by SAS and lives inside the encrypted payload; this cert is only the lock.

.EXAMPLE
    ./scripts/provision-jwe-key.ps1
    ./scripts/provision-jwe-key.ps1 -VaultName cyot-poc-kv -Kid cyot-poc-jwe-1
    ./scripts/provision-jwe-key.ps1 -SkipUpload    # local keys only, no Key Vault
#>
[CmdletBinding()]
param(
    [string]$VaultName = "cyot-poc-kv",
    [string]$Kid = "cyot-poc-jwe-1",
    # Secret name defaults to the kid so the Function resolves it automatically (no JWE_PRIVATE_KEY_SECRET needed).
    [string]$SecretName = $null,
    [string]$OutDir = "$PSScriptRoot/.keys",
    [switch]$SkipUpload
)

$ErrorActionPreference = "Stop"
if (-not $SecretName) { $SecretName = $Kid }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "Generating RSA-2048 keypair (test certificate)..."
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
try {
    $privatePem = $rsa.ExportPkcs8PrivateKeyPem()
    $publicPem = $rsa.ExportSubjectPublicKeyInfoPem()
}
finally {
    $rsa.Dispose()
}

$privatePath = Join-Path $OutDir "cyot-jwe-private.pem"
$publicPath = Join-Path $OutDir "cyot-jwe-public.pem"
Set-Content -Path $privatePath -Value $privatePem -NoNewline
Set-Content -Path $publicPath -Value $publicPem -NoNewline

Write-Host "  private -> $privatePath  (kept local, gitignored)"
Write-Host "  public  -> $publicPath   (share with SAS as the encryption cert)"

if ($SkipUpload) {
    Write-Host "`nSkipped Key Vault upload (-SkipUpload). To run the endpoint locally, set:"
    Write-Host "  `$env:CYOT_JWE_PRIVATE_KEY_PEM = Get-Content $privatePath -Raw"
}
else {
    Write-Host "`nUploading private key to Key Vault '$VaultName' secret '$SecretName'..."
    az keyvault secret set --vault-name $VaultName --name $SecretName --file $privatePath --tags "kid=$Kid" --output none
    if ($LASTEXITCODE -ne 0) { throw "Key Vault upload failed (need Key Vault Secrets Officer on $VaultName)." }
    Write-Host "  done. The Function resolves it by kid='$Kid' (secret name matches)."
    Write-Host "  If the secret name differs from the kid, set app setting JWE_PRIVATE_KEY_SECRET=$SecretName."
}

Write-Host "`n----- PUBLIC KEY (kid=$Kid) — give this to SAS -----"
Write-Host $publicPem
