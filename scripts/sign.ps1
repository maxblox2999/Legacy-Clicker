param([Parameter(Mandatory = $true)][string]$Executable)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') {
    throw 'Temporary signing is intended for GitHub-hosted build runners.'
}
$certificate = $null
try {
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=maxblox2999' -CertStoreLocation 'Cert:\CurrentUser\My' -Provider 'Microsoft Software Key Storage Provider' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(365)
    $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
    $signTool = Get-ChildItem -Path "$sdk/*/x64/signtool.exe" -File |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (!$signTool) { throw 'Microsoft SignTool was not found.' }
    & $signTool.FullName sign /s My /sha1 $certificate.Thumbprint /fd SHA256 /d maxblox2999 $Executable
    if ($LASTEXITCODE -ne 0) { throw 'SignTool signing failed.' }
    $verification = & $signTool.FullName verify /pa /v $Executable 2>&1 | Out-String
    $verifyExit = $LASTEXITCODE
    Write-Output $verification
    if ($verifyExit -ne 0 -and ($verification -notmatch '0x800B0109|root\s+certificate which is not trusted' -or $verification -notmatch 'Number of errors:\s+1')) {
        throw 'SignTool reported an error other than the expected untrusted self-signed root.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Executable
    if ($signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint -or $signature.Status -eq 'HashMismatch') {
        throw 'The executable signature does not match the signing certificate.'
    }
    @(
        'Publisher name: maxblox2999'
        'Signature: self-signed Authenticode, SHA-256'
        'This certificate is not issued by a trusted certificate authority.'
        'Windows may still display an untrusted-publisher or SmartScreen warning.'
        'The private key is created on the build runner, is not exported, and is deleted after signing.'
        "Public certificate thumbprint: $($certificate.Thumbprint)"
    ) | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $Executable) 'SIGNING.txt') -Encoding utf8
    Write-Output "Signed as maxblox2999; the self-signed root is not publicly trusted."
    $global:LASTEXITCODE = 0
}
finally {
    if ($certificate) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $certificate.Thumbprint) -DeleteKey -Force
    }
}
