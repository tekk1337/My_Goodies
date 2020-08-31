Write-Host "====AV Installed====" -ForegroundColor Yellow
" "
Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -match "trend|mcafee|eset|symantec|norton|bitdefender|sophos|kaspersky|avast|avg|avg|clamav|virus|endpoint protection|smart security|internet security" } | Select-Object -Property DisplayName | Out-Default
" "