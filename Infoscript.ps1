Clear-Host;
Function server-info 
{Write-Host "Hostname" -ForegroundColor Yellow
$env:COMPUTERNAME
Write-Host "Domain Information" -ForegroundColor Yellow
$domain = (Get-CimInstance Win32_ComputerSystem).Domain
If ($domain -like '*.*'){Write-Host "Domain Name: $domain"}Else{Write-Host "Domain Name: Not connected to domain"}
$OS = Get-CimInstance Win32_OperatingSystem | select -ExpandProperty Caption
$OSSP = (Get-CimInstance Win32_OperatingSystem | select -ExpandProperty ServicePackMajorVersion)
$OSArch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
Write-Host "OS" -ForegroundColor Yellow; "$OS $OSArch Service Pack $OSSP"
Write-Host "IP Address" -ForegroundColor Yellow
Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet* | select -ExpandProperty IPAddress
Write-Host "DNS IPs" -ForegroundColor Yellow
Get-DnsClientServerAddress -InterfaceAlias "Ethernet*"  | select -ExpandProperty ServerAddresses | Where-Object {$_ -notlike "*:*"}
Write-Host "CPU Information" -ForegroundColor Yellow
Get-CimInstance –class Win32_processor | ft DeviceID,NumberOfCores,NumberOfLogicalProcessors
Write-Host "Memory" -ForegroundColor Yellow 
$RAM = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB),2))}
Write-Host "$RAM GB"
Write-Host "Hard Drive Information" -ForegroundColor Yellow
$c=$env:COMPUTERNAME;$disks=gwmi win32_diskdrive -Comp $c|select __path,@{n="SCSI_Id";e={[string]$([int]$_.scsiport)+":"+$_.scsitargetid}},serialnumber,Type;function match($p,$l,$c){$l2p=gwmi win32_logicaldisktopartition -comp $c|?{$_.dependent -eq $l.__PATH};$d2p=gwmi win32_diskdrivetodiskpartition -comp $c|?{$_.dependent -eq $l2p.antecedent};$tmp=Get-WmiObject Win32_DiskPartition -comp $c|?{$_.__PATH -eq $l2p.Antecedent};$t=switch -Regex ($tmp.type){'^GPT'{'GPT'};'^Ins'{'MBR'};default{'unavailable'}}$p=$p|?{$_.__path -eq $d2p.antecedent};$p.Type=$t;$p};gwmi win32_logicaldisk -comp $c |?{$_.drivetype -eq '3'}|%{$d = match $disks $_ $c;New-Object psobject -Property @{Computer=$c;Drive=$_.deviceid;Name=$_.volumename;SCSIID=$d.SCSI_Id;SizeGB=[Math]::Round($_.size/1GB);FreeGB=[Math]::Round($_.FreeSpace/1GB);Serial=$d.serialnumber;Type=$d.Type}}|ft -a Computer,Name,Drive,Type,SCSIID,FreeGB,SizeGB,Serial}
#Get-WmiObject -Class Win32_logicaldisk -Filter "DriveType = '3'" | Select-Object -Property DeviceID, VolumeName, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}} | Out-Default}
#server-info
function Get-Uptime {
   $os = Get-WmiObject win32_operatingsystem
   $uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
   $Display = "Uptime: " + $Uptime.Days + " days, " + $Uptime.Hours + " hours, " + $Uptime.Minutes + " minutes" 
   $lastboottime = Get-CimInstance CIM_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
   Write-Host "System Uptime" -ForegroundColor Yellow
   Write-Output $Display
   Write-Host "Last Rebooted:" $lastboottime 
}
#Clear-Host
#Get-Uptime
function Test-PendingReboot
{
Write-Host "Pending Reboot" -ForegroundColor Yellow
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
#Test-PendingReboot
Function AV-Check
{Write-Host "Installed Antivirus Software" -ForegroundColor Yellow
$ErrorActionPreference = "SilentlyContinue"
$antivirus = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -match "trend|mcafee|eset|symantec|norton|bitdefender|sophos|kapersky|avast|avg|avg|clamav|virus|endpoint protection|smart security|internet security" } | Select-Object -Property DisplayName | Select -ExpandProperty DisplayName
If ($antivirus -eq $null){Write-Host "No Antivirus Installed"}Else{$antivirus}}
#AV-Check
Function Trend-PortCheck
{$trend4119 = New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4119) | select -ExpandProperty Connected
$trend4120 = New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4120) | select -ExpandProperty Connected
$trend4122 = New-Object System.Net.Sockets.TcpClient("3a.epsec.armor.com", 4122) | select -ExpandProperty Connected
Write-Host "Trend Port Connectivity" -ForegroundColor Yellow
Write-Output "Port 4119 Connected: $trend4119"
Write-Output "Port 4120 Connected: $trend4120"
Write-Output "Port 4121 Connected: $trend4122"
}
#Trend-PortCheck
Function Patch-Check
{Write-Host "Installed Patches" -ForegroundColor Yellow
Get-HotFix | Select-Object -Property Description,HotFixID,InstalledOn | Select-Object -Last 5 | Sort-Object -Descending | Format-Table}
#Patch-Check
Function Cipher-Check
{
$ErrorActionPreference = "SilentlyContinue"
Write-Host "Protocols and Ciphers" -ForegroundColor Yellow
$tls = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*\* | ft @{n='protocol';e={($_.pschildname) +"-"+ ($_.pspath).split("\")[-2]}},Enabled,DisabledByDefault -auto;"Ciphers","Hashes","KeyExchangeAlgorithms" | foreach{$c=$_;Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\$c\*" |ft @{n="$c";e={($_.pspath).split("\")[-2]}},Enabled -auto};(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002').Functions.split(',')
If ($tls -eq $null){Write-Host "Server Defaults Only"}Else{$tls}
}
#Cipher-Check
Function Software-check
{Write-Host "Software Check" -ForegroundColor Yellow
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
        '^15' { "Microsoft SQL Server 2019" }
        Default { "Unsupported version." }
    }
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
""
$iis = (Get-WindowsFeature web-server).InstallState
if ($iis -eq "Installed") {Write-Host "IIS is Installed"} Else {Write-Host "IIS is NOT Installed"}}
#SQL-VersionCheck
Function Armor-Services
{Write-Host "Armor Subagent Service Status" -ForegroundColor Yellow
$services = @{}
$servicenames = @('AMSP','ds_agent', 'Armor-Filebeat', 'Armor-Winlogbeat', 'Bomgar', 'QualysAgent', 'PanoptaAgent')
Foreach ($servicename in $servicenames ) {
    try {
        $servicestatus = Get-Service $servicename -ErrorAction Stop | select -ExpandProperty status
        
    } catch {
        $servicestatus = 'Not Installed'        
    }
    $services.Add($servicename , $servicestatus)
}
New-Object psobject -Property $services | Out-Default
#Armor-Services
}
$ErrorActionPreference = "SilentlyContinue"
Function Agent-Info
{
$ErrorActionPreference = 'silentlycontinue'
$armoragent = gsv armor-agent | select -ExpandProperty Status
If ($armoragent -eq $null) {Write-Host "Armor Agent Status: Not Installed"}Else{Write-Host "Armor Agent Status: $armoragent"}
}
Function Agent-Version
{
Write-Host "Armor Agent Information" -ForegroundColor Yellow
$agentversion = C:\.armor\opt\armor.exe --v
$agentversion = $agentversion.split(" ")[2]
If ($agentversion -eq $null){Write-Host "Armor Agent is not installed"}Else{Write-Host "Armor Agent Version: $agentversion"}
}
$ErrorActionPreference = "SilentlyContinue"
Function show-subagents
{
$output = @()
$reg = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty
"Trend","Panopta","Qualys" | ForEach-Object {
    $tmpout = '' | select Subagent,Version,Installed
    $tmpout.Subagent = $_
    $key = $reg | Where-Object { $_ -match $tmpout.Subagent }
    $tmpout.Installed = ( -not [string]::IsNullOrEmpty($key) )
    $tmpout.Version = try{ $key[0].displayversion } catch {$null}
        
    $output+= $tmpout
}
'Filebeat','Winlogbeat' | ForEach-Object {
    $tmpout = '' | select Subagent,Version,Installed
    $tmpout.Subagent = $_
    try {
        $filepath = Get-Item -Path "c:\.armor\opt\$_*" -ErrorAction Stop | Where-Object{$_.PSIsContainer} | select -First 1
        $tmpout.Installed = $true
        $tmpout.Version = ($filepath.Name | Select-String "\d\.\d\.\d").Matches[0].Value
    } catch {
        $tmpout.Installed = $false
        $tmpout.Version = $null
    }
    $output += $tmpout
}
$output
}

server-info
Get-Uptime
Test-PendingReboot
AV-Check
Trend-PortCheck
Patch-Check
Cipher-Check
Software-check