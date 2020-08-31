$OS = Get-CimInstance Win32_OperatingSystem | select -ExpandProperty Caption
$OSSP = (Get-CimInstance Win32_OperatingSystem | select -ExpandProperty ServicePackMajorVersion)
$OSArch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
Write-Host "OS" -ForegroundColor Yellow; "$OS $OSArch Service Pack $OSSP"
Write-Host "System Uptime" -ForegroundColor Yellow
function Get-Uptime {
   $os = Get-WmiObject win32_operatingsystem
   $uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
   $Display = "Uptime: " + $Uptime.Days + " days, " + $Uptime.Hours + " hours, " + $Uptime.Minutes + " minutes" 
   Write-Output $Display
}
Get-Uptime
function Test-PendingReboot
{
 if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
 if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
 if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
 try { 
   $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
   $status = $util.DetermineIfRebootPending()
   if(($status -ne $null) -and $status.RebootPending){
     return $true
   }
 }catch{}

 return $false
}
Write-Host "Pending Reboot" -ForegroundColor Yellow
Test-PendingReboot
Write-Host "Installed Antivirus Software" -ForegroundColor Yellow
$ErrorActionPreference = "SilentlyContinue"
$antivirus = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -match "trend|mcafee|eset|symantec|norton|bitdefender|sophos|kapersky|avast|avg|avg|clamav|virus|endpoint protection|smart security|internet security" } | Select-Object -Property DisplayName | Select -ExpandProperty DisplayName
If ($antivirus -eq $null){Write-Host "No Antivirus Installed"}Else{$antivirus}
$trend4119 = New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4119) | select -ExpandProperty Connected
$trend4120 = New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4120) | select -ExpandProperty Connected
$trend4122 = New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4122) | select -ExpandProperty Connected
$armorapi = New-Object System.Net.Sockets.TcpClient("api.armor.com", 443) | select -ExpandProperty Connected
$armorlog1 = New-Object System.Net.Sockets.TcpClient("1a.log.armor.com", 515) | select -ExpandProperty Connected
$remoteaccess = New-Object System.Net.Sockets.TcpClient("1a.rs.armor.com", 443) | select -ExpandProperty Connected
$logrelay = New-Object System.Net.Sockets.TcpClient("1c.log.armor.com", 5443) | select -ExpandProperty Connected
Write-Host "Port Connectivity" -ForegroundColor Yellow
Write-Output "API Connected:                                          $armorapi"
Write-Output "Log Management (Filebeat/Winlogbeat) Connected:         $armorlog1"
Write-Output "Remote Access Connected:                                $remoteaccess"
Write-Output "Log Relay Connected:                                    $logrelay"
Write-Output "(Trend)Port 4119 Connected:                             $trend4119"
Write-Output "(Trend)Port 4120 Connected:                             $trend4120"
Write-Output "(Trend)Port 4122 Connected:                             $trend4122"
Write-Host "Armor Subagent Service Status" -ForegroundColor Yellow
$services = @{}
$servicenames = @('AMSP', 'Armor-Filebeat', 'Armor-Winlogbeat', 'Bomgar', 'QualysAgent', 'PanoptaAgent')
Foreach ($servicename in $servicenames ) {
    try {
        $servicestatus = Get-Service $servicename -ErrorAction Stop | select -ExpandProperty status
        
    } catch {
        $servicestatus = 'Not Installed'
        
    }
    $services.Add($servicename , $servicestatus)
}
New-Object psobject -Property $services | Out-Default
Write-Host "Armor Agent Version and Status" -ForegroundColor Yellow
$ErrorActionPreference = "SilentlyContinue"
#$armoragent = $null;
$armordb = $null;
$armorid = Get-Content C:\.armor\armor-id
#$armoragent = C:\.armor\opt\armor.exe show subagents
$armordb = C:\.armor\opt\armor.exe show db
#If ($armoragent -ne $null)
{
""
Write-Host "Armor Agent ID: $armorid"
""
#$armoragent
$armordb
}
Else
{
Write-Host "Armor Agent Not Installed";
} 