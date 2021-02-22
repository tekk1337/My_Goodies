Function Protocolcheck
{
Write-Host "Protocols" -ForegroundColor Yellow
$ErrorActionPreference = "SilentlyContinue"
$OScheck = Get-CimInstance Win32_OperatingSystem | select -ExpandProperty Caption | Select-String -Pattern '20\d\d' | ForEach-Object { $_.Matches.Value }
$SSL2 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' | select -ExpandProperty Enabled
$SSL3 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' | select -ExpandProperty Enabled
$tls10 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' | select -ExpandProperty Enabled
$tls11 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' | select -ExpandProperty Enabled
$tls12 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' | select -ExpandProperty Enabled
If ($tls10 -eq 0 -or $tls10 -eq $null){Write-Host "TLS 1.0 is Disabled"}Else{Write-Host "TLS 1.0 is Enabled"}
If ($OScheck -gt 2012)
    {
    If ($tls11 -eq 0) {Write-Host "TLS 1.1 is Disabled"}Else{Write-Host "TLS 1.1 is Enabled"}
    If ($tls12 -eq 0) {Write-Host "TLS 1.2 is Disabled"}Else{Write-Host "TLS 1.2 is Enabled"}
}Else{
    If ($tls11 -eq 0 -eq $null) {Write-Host "TLS 1.1 is Disabled"}Else{Write-Host "TLS 1.1 is Enabled"}
    If ($tls12 -eq 0 -eq $null) {Write-Host "TLS 1.2 is Disabled"}Else{Write-Host "TLS 1.2 is Enabled"}
}}
function CipherCheck {
Write-Host "Ciphers" -ForegroundColor Yellow
$ciphercheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002\ -Name Functions | select -ExpandProperty Functions | Out-Default
$ciphercheck2 = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003\ -Name Functions | select -ExpandProperty Functions | Out-Default
Write-Host "$ciphercheck $ciphercheck2"}

Protocolcheck
""
Ciphercheck