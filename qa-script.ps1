Clear-Host;
Write-Host "Hostname" -ForegroundColor Yellow
$env:COMPUTERNAME
$OS = Get-CimInstance Win32_OperatingSystem | select -ExpandProperty Caption
$OSSP = (Get-CimInstance Win32_OperatingSystem | select -ExpandProperty ServicePackMajorVersion)
$OSArch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
Write-Host "OS" -ForegroundColor Yellow; "$OS $OSArch Service Pack $OSSP"
Write-Host "IP Address" -ForegroundColor Yellow
Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet* | findstr IPAddress
Write-Host "CPU Information" -ForegroundColor Yellow
Get-CimInstance –class Win32_processor | ft DeviceID,NumberOfCores,NumberOfLogicalProcessors
Write-Host "Memory" -ForegroundColor Yellow 
$RAM = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB),2))}
Write-Host "$RAM GB"
Write-Host "Hard Drive Information" -ForegroundColor Yellow
Get-WmiObject -Class Win32_logicaldisk -Filter "DriveType = '3'" | Select-Object -Property DeviceID, VolumeName, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}} | Out-Default
Write-Host "System Uptime" -ForegroundColor Yellow
function Get-Uptime {
   $os = Get-WmiObject win32_operatingsystem
   $uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
   $Display = "Uptime: " + $Uptime.Days + " days, " + $Uptime.Hours + " hours, " + $Uptime.Minutes + " minutes" 
   Write-Output $Display
}
 
#Clear-Host
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
#$trend4119 = New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4119) | select -ExpandProperty Connected
#$trend4120 = New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4120) | select -ExpandProperty Connected
#$trend4122 = New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4122) | select -ExpandProperty Connected
#Write-Host "Trend Port Connectivity" -ForegroundColor Yellow
#Write-Output "Port 4119 Connected: $trend4119"
#Write-Output "Port 4120 Connected: $trend4120"
#Write-Output "Port 4121 Connected: $trend4122"
Write-Host "Installed Patches" -ForegroundColor Yellow
Get-HotFix | Select-Object -Property Description,HotFixID,InstalledOn | Select-Object -Last 5 | Sort-Object -Descending | Format-Table
Write-Host "Protocols and Ciphers" -ForegroundColor Yellow
$tls = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*\* | ft @{n='protocol';e={($_.pschildname) +"-"+ ($_.pspath).split("\")[-2]}},Enabled,DisabledByDefault -auto;"Ciphers","Hashes","KeyExchangeAlgorithms" | foreach{$c=$_;Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\$c\*" |ft @{n="$c";e={($_.pspath).split("\")[-2]}},Enabled -auto};(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002').Functions.split(',')
If ($tls -eq $null){Write-Host "Server Defaults Only"}Else{$tls}
Write-Host "SQL Software" -ForegroundColor Yellow
$ErrorActionPreference = 'silentlycontinue'
If (Test-Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server') {
$inst = (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances
foreach ($i in $inst)
{
    $p = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL').$i
    #$i
    $edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Edition
    $version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Version
    $product = Switch -regex ($version) {
        '^10' { "Microsoft SQL Server 2008/R2" }
        '^11' { "Microsoft SQL Server 2012" }
        '^12' { "Microsoft SQL Server 2014" }
        '^13' { "Microsoft SQL Server 2016" }
        '^14' { "Microsoft SQL Server 2017" }
        Default { "Unsupported version." }
    }

    #$sql = [PSCustomObject]@{
    #'Instance'         = $i
    #'Product'          = $product
    #'Edition'          = $edition
    #'Version'          = $version
    #}
    #$sql | fl
    
    Write-Host ""
    #Write-Host "Instance: $i"
    Write-Host "Product: $product"
    Write-Host "Edition: $edition"
    Write-Host "Version: $version"
    Write-Host ""
}
}Else{
Write-Host "SQL Software not installed"
}
#Write-Host "Armor Agent Version and Status" -ForegroundColor Yellow
#$ErrorActionPreference = "SilentlyContinue"
#$armoragent = $null;
#$armordb = $null;
#$armoragent = C:\.armor\opt\armor.exe show subagents
#$armordb = C:\.armor\opt\armor.exe show db
#$armorversion = C:\.armor\opt\armor.exe --v
#If ($armoragent -ne $null)
#{
#$armorversion
#$armoragent
#$armordb
#}
#Else
#{
#Write-Host "Armor Agent Not Installed";
#} 
#Write-Host "Armor Subagent Service Status" -ForegroundColor Yellow
#$services = @{}
#$servicenames = @('AMSP', 'Armor-Filebeat', 'Armor-Winlogbeat', 'Bomgar', 'ir_agent', 'PanoptaAgent')
#Foreach ($servicename in $servicenames ) {
#    try {
#        $servicestatus = Get-Service $servicename -ErrorAction Stop | select -ExpandProperty status
#        
#    } catch {
#        $servicestatus = 'Not Installed'
#       
#    }
#    $services.Add($servicename , $servicestatus)
#}
#New-Object psobject -Property $services | Out-Default
Write-Host "Installed Windows Features" -ForegroundColor Yellow
$ErrorActionPreference = "SilentlyContinue"
$WindowsFeatures = Get-WindowsFeature | Where InstallState -eq Installed | ft -a
If ($WindowsFeatures -eq $null){Write-Host "This feature only exists in Windows Server OS's"}Else{$WindowsFeatures}
#Write-Host "System Error Logs" -ForegroundColor Yellow
#Get-EventLog -LogName System -EntryType Warning,Error -Newest 10 | ft -Wrap
#Write-Host "Application Error Logs" -ForegroundColor Yellow
#Get-EventLog -LogName Application -EntryType Warning,Error -Newest 10 | ft -Wrap
#ConvertTo-Html | Out-File C:\wininfo.html