###############
# System Info #
###############
#region System Info
#Get System Boot Time
gwmi win32_operatingsystem |ft -a @{n='ComputerName';e={$_.csname}},@{name="BootTime"; Expression={$_.Converttodatetime($_.LastBootUpTime)}}

#Get System Uptime
$up = (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).LocalDateTime) - (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime($(Get-WmiObject Win32_OperatingSystem).LastBootUpTime);New-Object psobject |Add-Member NoteProperty Uptime "$($up.Days) days, $($up.Hours)h, $($up.Minutes)mins" -PassThru

$c='localhost';$os=gwmi win32_operatingsystem -ComputerName $c;$t = $os.ConvertToDateTime($os.LocalDateTime)-$os.ConvertToDateTime($os.LastBootUpTime);"`n$($t.days) Days, $($t.hours) h, $($t.minutes) mins`n"
(Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).LocalDateTime) - (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime($(Get-WmiObject Win32_OperatingSystem).LastBootUpTime);

New-Object psobject |Add-Member NoteProperty Uptime "$($up.Days) days, $($up.Hours)h, $($up.Minutes)mins" -PassThru


#query domain info
[System.Reflection.Assembly]::LoadWithPartialName('System.DirectoryServices') | Out-Null; [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()


#panopta manual install:
msiexec.exe /i C:\panopta\panopta-agent-prod-v17.28.1.msi MANIFESTFILE="C:\.armor\opt\panopta.manifest" /L*V C:\panoptainstall.log

#Show file extentions
New-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ -Name HideFileExt -Value 0 -PropertyType dword -Force

#list WSUS Policy(client side)
gp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\" |select @{n='Name';e={$env:COMPUTERNAME}},@{n='UpdateServer';e={(gp -Path $_.psparentpath).wuserver}},usewuserver,@{n='AUOption';e={switch($_.auoptions){"1" {"NoCheck"}"2"{"CheckOnly"}"3"{"DownloadOnly"}"4"{"Install"}"default"{"N/A"}}}},NoAutoUpdate,@{n='ScheduledInstallDay';e={switch($_.ScheduledInstallDay){"0"{"Everyday"}"1"{"Sunday"}"2"{"Monday"}"3"{"Tuesday"}"4"{"Wednesday"}"5"{"Thursday"}"6"{"Friday"}"7"{"Saturday"}"Default"{"N/A"}}}},ScheduledInstallTime,DetectionFrequency,DetectionFrequencyEnabled,AlwaysAutoRebootAtScheduledTime,AlwaysAutoRebootAtScheduledTimeMinutes

#kill service local or remote
#start CMD, not powershell
sc \\servername queryex SERVICENAME
taskkill /S COMPUTERNAME /f /pid 1234

#set password to never expire
WMIC USERACCOUNT WHERE "Name='armoradmin'" SET PasswordExpires=FALSE


#Get Pagefile:
Get-WmiObject Win32_PageFileusage | Select-Object Name,@{n='SizeGB';e={$_.AllocatedBaseSize/1024}},PeakUsage

# List services on svchst
tasklist /svc /FI "IMAGENAME eq svchost.exe"




#endregion

###############################
# Security Policy Management  #
###############################
#region Security Policy Management
#Lighten security on test boxes
$policylocation = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$values = 'EnableLUA','ConsentPromptBehaviorAdmin','FilterAdministratorToken'
#UAC Disable ( 0=enabled 1=enabled)
gp $policylocation | fl $values
$values | foreach-object {Set-ItemProperty $policylocation -Name $_ -Value 0}
Set-ItemProperty $policylocation -Name legalnoticetext -Value "This server is intended as a testing server to guage Engineer abilities. Please do not use this server for anything else!!!"

# Disable RDP timeouts
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name inactivitytimeoutsecs -Value 0
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name Shadow -PropertyType dword -Value 4 -Force | out-null
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name disablepasswordsaving -PropertyType dword -Value 4 -Force | out-null


<#
Event ID: 4688
Token Elevation Type: Token elevation is about User Account Control
%%1936  - Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.
%%1937 - Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  
    An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.
%%1938 - Type 3 is the normal value when UAC is enabled and a user simply starts a program from the Start Menu.  It's a limited token with administrative privileges removed and administrative groups disabled.  
    The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.
#>


#uninstall app via registry:
$appsearch = 'rubrik'
$uninstallstring = gci HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall,HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall|gp|where{$_.displayname -match $appsearch}


if ($uninstall64) {
$uninstall64 = $uninstall64.UninstallString -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X",""
$uninstall64 = $uninstall64.Trim()
Write "Uninstalling..."
start-process "msiexec.exe" -arg "/X $uninstall64 /qb" -Wait}
if ($uninstall32) {
$uninstall32 = $uninstall32.UninstallString -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X",""
$uninstall32 = $uninstall32.Trim()
Write "Uninstalling..."
start-process "msiexec.exe" -arg "/X $uninstall32 /qb" -Wait}
#endregion

##############
# Networking #
##############
#region Networking
#Test Port(works in all PS versions)
(New-Object System.Net.Sockets.TcpClient('IP_ADDRESS', 'port')).Connected

#show TLS version
[Net.ServicePointManager]::SecurityProtocol


#change TLS version
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::SecurityProtocol = "Tls12","TLS11","TLS"

$content = @'
<?xml version="1.0"?>
<configuration>
<startup useLegacyV2RuntimeActivationPolicy="true">
<supportedRuntime version="v4.0.30319"/>
<supportedRuntime version="v2.0.50727"/>
</startup>
</configuration>
'@
Add-Content -Path "$pshome\powershell.exe.config" -Value $content -Force
powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::SecurityProtocol


#list current TLS reg settings
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*\* | ft @{n='protocol';e={($_.pspath).split("\")[-2]}},Enabled,DisabledByDefault -auto
#check all cipher settings
$ErrorActionPreference='silentlycontinue'; Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\*\* | ft @{n='protocol';e={($_.pschildname) +"-"+ ($_.pspath).split("\")[-2]}},Enabled,DisabledByDefault -auto;"Ciphers","Hashes","KeyExchangeAlgorithms" | foreach{$c=$_;Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\$c\*" |ft @{n="$c";e={($_.pspath).split("\")[-2]}},Enabled -auto};(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002').Functions.split(',')

#set TLS 1.2 as default protocol
#This patch required: http://www.catalog.update.microsoft.com/search.aspx?q=kb3140245
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DefaultSecureProtocols' -PropertyType DWORD -Value ([uint32](0x800)) -Force 
New-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DefaultSecureProtocols' -PropertyType DWORD -Value ([uint32](0x800)) -Force

Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' | ft -a DefaultSecureProtocols
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'|ft -a DefaultSecureProtocols

$path = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4* 
$path86 = Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4* 
New-ItemProperty -Path $path.PSPath -Name SchUseStrongCrypto -PropertyType dword -Value 1 -Force
New-ItemProperty -Path $path86.PSPath -Name SchUseStrongCrypto -PropertyType dword -Value 1 -Force


#Download Ciphercheck ASP Script and run:
(New-Object system.net.webclient).downloadfile('https://drive.google.com/uc?authuser=0&id=0B5ba0j5PADCdcGlFbGEzRjV2RVE&export=download', "$env:userprofile\Desktop\ciphercheck.asp")
#then, copy the file to the root of the web folder
Import-Module Servermanager; if((Get-WindowsFeature -Name Web-Asp).InstallState -ne 'Installed'){Install-WindowsFeature -Name Web-Asp}



#List Installed .NET Versions
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version,Release -EA 0 | Where { $_.PSChildName -match '^(?!S)\p{L}'} | Select PSChildName, Version, Release


#check for port exhaustion
Get-WinEvent -FilterHashtable @{'logname'='system';'providername'='tcpip';'id'='4231'} -MaxEvents 5 | ft timecreated,message -wr -a
#more port exhaustion stuff
Get-NetTCPConnection |group State | select count,name
Get-NetTCPConnection -State Bound |group owningprocess | select count,@{n='PID';e={$_.name}},@{n='processname';e={(Get-Process -Id $_.name).Name}}


#disable IPv6
Set-ItemProperty -Path hklm:\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters -name DisabledComponents -value 0xffffffff

#disable TCP Offloading
Get-NetAdapterAdvancedProperty -RegistryKeyword "*IPChecksumOffloadIPv4","*LsoV2IPv4","*LsoV2IPv6","*TCPChecksumOffloadIPv4","*TCPChecksumOffloadIPv6"
Set-NetAdapterAdvancedProperty -RegistryKeyword "*IPChecksumOffloadIPv4","*LsoV2IPv4","*LsoV2IPv6","*TCPChecksumOffloadIPv4","*TCPChecksumOffloadIPv6" -DisplayValue disabled

 where {$_.RegistryKeyword -eq 
 "*IPChecksumOffloadIPv4" -or $_.RegistryKeyword -eq
  "*LsoV2IPv4" -or $_.RegistryKeyword -eq 
  "*LsoV2IPv6" -or $_.RegistryKeyword -eq 
  "*TCPChecksumOffloadIPv4" -or $_.RegistryKeyword -eq 
  "*TCPChecksumOffloadIPv6"}

#add static route
route -p add IP_address mask subnet_mask gateway

#Get list of IPs with skipassource Flag. Works with PSv2
$netsharray = @();$ipmatch = @();$skipmatch=@();$IPaddresses = (netsh int ip show ipaddresses level=verb |Select-String -Pattern "^Address.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");foreach($IPaddress in $IPaddresses){$ipmatch += $ipaddress.tostring().trim("Address").trim("Paramter").trim(" ").split("")};$skipassources = (netsh int ip show ipaddresses level=verb |select-string -Pattern "Skip as Source");foreach($line in $skipassources){$skipmatch += $line.tostring().trimstart("Skip as Source     :").split("")};0..($ipmatch.count - 1) |ForEach-Object {$temp2 = New-Object psobject -Property @{IPAddress = $ipmatch[$_].tostring();Skipassource = $skipmatch[$_].tostring()};$netsharray += $temp2};$netsharray

#Remove NIC DNS Registration
Get-NetAdapter ADAPTERNAME | Set-DNSClient –RegisterThisConnectionsAddress $False

#set client dns
Get-NetAdapter ethernet0 | set-DnsClientServerAddress -ServerAddresses @('100.64.206.34')

#test ssl client ciphers:
(New-Object system.net.webclient).DownloadString("https://www.howsmyssl.com/a/check").split("{[,:]}")|where{$_ -notlike ""}
(Invoke-WebRequest https://www.howsmyssl.com/a/check |select -ExpandProperty content).split("{,}")

Invoke-RestMethod https://www.howsmyssl.com/a/check |select tls_version,@{n='Ciphers';e={"$($_.given_cipher_suites)"}} | ConvertTo-Json

#List Installed .NET Versions
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version,Release -EA 0 | Where { $_.PSChildName -match '^(?!S)\p{L}'} | ft -AutoSize PSChildName, Version, Release

#send test email
Send-MailMessage –From sender@testserverdomain.com –To recipient@recipientdomain.com –Subject “Test Email” –Body “Test E-mail” -SmtpServer smtpserver.fqdndomain.local
#more intricate
$passwd = ConvertTo-SecureString 'NotMyPassword' -AsPlainText -force
$creds = New-Object System.Management.Automation.PSCredential ("brandonspell08@hotmail.com", $passwd)
$mailparams = @{
    To = 'brandon.spell@armor.com'
    From = 'brandonspell08@hotmail.com'
    Subject = 'Automated Test Email'
    Body = 'This has been a test of the test testing system'
    SmtpServer = 'smtp.office365.com'
    Port = '587'
    Credential = $creds
    UseSSL = $true
}
Send-MailMessage @mailparams


(New-Object system.net.webclient).downloadfile("https://www.microsoft.com/en-us/download/confirmation.aspx?id=49996","$env:userprofile\desktop\sqlserver2012SP3")
#download File
#winactivation
(New-Object system.net.webclient).downloadfile('https://codeplexarchive.blob.core.windows.net/archive/projects/PerfTesting/PerfTesting.zip', "C:\Users\bspell\Downloads\PerTesting.zip")
#appcrashview
(New-Object system.net.webclient).downloadfile("https://drive.google.com/uc?id=0B5ba0j5PADCdbWRHR0psNm5mNU0&export=download","$env:userprofile\desktop\appcrashview.zip")
#AD Replication Status Checker Tool
(New-Object system.net.webclient).downloadfile("https://download.microsoft.com/download/6/8/8/688FFD30-8FB8-47BC-AD17-0E5467E4E979/adreplstatusInstaller.msi","$env:userprofile\desktop\adreplstatusinstaller.msi")

#web request
try{([system.net.webrequest]::create("http://google.com/bananachickennugget.asp")).getresponse().statuscode}catch [system.net.webexception]{$_.exception.response.statuscode}

#test port(Function)
#example: Test-Port google.com 443
function Test-Port($ip, $port){$t = New-Object Net.Sockets.TcpClient;try{$t.Connect($ip,$port)}catch{};if($t.Connected){$t.Close();$status = "open";$color = "green"}else{$status = "closed";$color = "red"};Write-Host "Port $port on $ip is " -NoNewline;Write-Host $status -foregroundcolor $color}
#new
function Test-Port($ip, [int]$port, [int]$count=1){while($count -ne 0){$t = New-Object Net.Sockets.TcpClient;$res = $t.BeginConnect( $ip, $port, $null, $null).AsyncWaitHandle.WaitOne(3000,$false);New-Object psobject -Property @{'Host'= $ip;'Port' = $port;'Status' = switch($res){$true {"Open"};$false {"Closed"}}};$count--}}

#create listener:
$tcplistener = [System.Net.Sockets.TcpListener]::new('100.64.206.32', '456')
$tcplistener.Start()
$tcplistener.Stop()

#get-site function
#example: get-site https://www.google.com
function Get-Site{param([Parameter(Mandatory=$true)][string]$url,[ValidatePattern("^/.")][string]$path,[validateset('http','https')][string]$protocol='http')function test-port($url,$p){$t = New-Object Net.Sockets.TcpClient;try{$t.Connect($url,$p);return $true}catch{return $false}};$uri = $protocol+"://"+$url+$path;switch($protocol){"http"{$p = '80'};"https"{$p = '443'}};$ErrorActionPreference = "stop";if(test-port $url $p){$webRequest = [net.WebRequest]::Create($uri);$then = get-date;Try{$response = $webRequest.GetResponse();$now=Get-Date;$report = [ordered]@{StatusCode = $response.Statuscode -as [int];StatusDescription = $response.StatusDescription;ResponseTime = "$(($now - $then).totalseconds)";WebServer = $response.Server;URL = $uri};New-Object PSObject -property $report}Catch [system.net.webexception]{$report = [ordered]@{StatusCode = $($_.exception.response.statuscode) -as [int];StatusDescription = "$($_.exception.response.statusdescription)";ResponseTime = "$(($now - $then).totalseconds)";URL = $uri;Error = "$($_.exception.message)"};New-Object PSObject -property $report}}else{Write-Warning "Could no establish connection to $uri"}}


# INstall Rubrik agent:
[System.Net.ServicePointManager]::SecurityProtocol = 'TLS12'
Add-Type -assembly "System.IO.Compression.FileSystem"
$path = $env:USERPROFILE +'\desktop\RubrikBackupService.zip'
#DFW
Invoke-WebRequest https://get.core.armor.com/backup/DFW01/RubrikBackupService.zip -OutFile $path
#PHX
Invoke-WebRequest https://get.core.armor.com/backup/PHX01/RubrikBackupService.zip -OutFile $path
[IO.Compression.ZipFile]::ExtractToDirectory($path, $path.TrimEnd('.zip'))
$installfile = (gci $path.TrimEnd('.zip') -Filter '*.msi').fullname
& @installfile /qb /L*v $($path.TrimEnd('.zip')+'\RubrikInstall.log')


#DFW
Invoke-WebRequest https://get.core.armor.com/backup/DFW01/RubrikBackupService.zip -OutFile $path
#PHX
Invoke-WebRequest https://get.core.armor.com/backup/PHX01/RubrikBackupService.zip -OutFile $path
[IO.Compression.ZipFile]::ExtractToDirectory($path, $path.TrimEnd('.zip'))
$installfile = (gci $path.TrimEnd('.zip') -Filter '*.msi').fullname
& @installfile /qb /L*v $($path.TrimEnd('.zip')+'\RubrikInstall.log')


#Configure NTLM
#Get Setting:
gp HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -PSProperty lmcompatibilitylevel
<#
0 - Send LM & NTLM responses
1 - Send LM & NTLM – use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only. Refuse LM
5 - Send NTLMv2 response only. Refuse LM & NTLM

For Ideal Backwards compatibility, either Do not use 4 or 5.
#>
#Set NTLM Setting
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name lmcompatibilitylevel -Value 2


#endregion

###############
# File System #
###############
#region File System
#Copy Permissions between Directories
(get-item 'C:\PATH\TO\COPY\PERMISSONS\FROM').GetAccessControl("Access") |set-acl -Path 'C:\PATH\TO\COPY\PERMISSIONS\TO'

#Recursively find string in all files in directory
Get-ChildItem -path 'E:\Powershell Scripts\VMware' -recurse | Select-String -pattern "VirtualDevice.FlatHardDiskImpl" | group path | select name
#MORE EFFICIENT:
$query = 'Provider='
$results = Get-ChildItem -path 'D:\' -recurse -ErrorAction SilentlyContinue | Select-String -pattern 'yanlufOng' | group path | select name


#Get file version info
(Get-Item -Path "C:\path\to\file").VersionInfo | Format-Table -Property "FileMajorPart", "FileMinorPart", "FileBuildPart", "FilePrivatePart" -AutoSize


Get-ChildItem -path 'D:\Program Files\Elixir Technologies\Tango\server\tomcat' -recurse | Select-String -pattern "8444" -SimpleMatch | group path | select name
#endregion

##########
# Memory #
##########
#region Memory
#check Installed Memory

gwmi win32_operatingsystem | select pscomputername,@{n="MemoryGB";e={[math]::round($_.totalvisiblememorysize/1MB)}}
function Get-Memory{[CmdletBinding()]param([parameter(ValueFromPipeline=$true)][string[]]$computer=$env:COMPUTERNAME)begin{[System.Collections.ArrayList]$results = @()}process{foreach($comp in $computer){try{$tmp = gwmi win32_operatingsystem -ComputerName $comp -ErrorAction Stop| select pscomputername,@{n="MemoryGB";e={[math]::round($_.totalvisiblememorysize/1MB)}};$results.Add($tmp)|Out-Null;}catch{Write-Warning ("{0}`t-`tCould not connect!!" -f $comp)}}}end{return $results}}

#Query Domain info:
[System.Reflection.Assembly]::LoadWithPartialName('System.DirectoryServices') | Out-Null; [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

#check memory every x seconds:
while ($true){Get-Counter -Counter "\Memory\Available MBytes";Start-Sleep -s "1"}

#check desktop heap exhaustion
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems').Windows.split(" ")|Select-String "SharedSection"
#Change Desktop Heap Settings:
$heapmemsetting = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems').Windows
$newheapsetting = $heapmemsetting.Replace('SharedSection=\d\d\d\d,\d\d\d\d\d,\d\d\d ','Windows SharedSection=1111,11110,1111')
#endregion

###############################
# Armor Agent Troubleshooting #
###############################
#region Armor Agent Troubleshooting
# enable debug log:
$data = @'
LogLevel=debug
ClientLogging=true
'@
New-Item c:\.armor\etc\armor.cfg -ItemType File -Value $data

#download bomgar
$bin = 'https://get.core.armor.com/remotesupport/bomgar-pec-win64.msi'
Invoke-WebRequest $bin -outfile $home\Desktop\bomgar.msi
msiexec /quiet /i bomgar.msi KEY_INFO=w0idc30ighwwde5gd1jzz7i16zj816yxjgzg877c40jc90 jc_tag=4860 jc_comments=a098afb4-d29c-4b3e-87cd-f040e803cc79 /l

#set armor agent to delayed autostart
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\armor-agent | ft -a DelayedAutoStart
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\armor-agent -Name DelayedAutostart -Value 1 -PropertyType dword -Force | out-null;start-service armor-agent -PassThru



#Trend:

#heartbeat
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -m

#Get info
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_query" -c GetComponentInfo
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_query" -c GetHostInfo
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_query" -c GetAgentStatus

#reset and re-register
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -r

& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -a dsm://3a.epsec.armor.com:4120/ "hostname:<acct>__<coreinstanceid>"

#generage diag package
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -d

#download latest agent
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
(New-Object System.Net.WebClient).DownloadFile( "https://3a.epsec.armor.com:4119/software/agent/Windows/x86_64/", "$home\desktop\agent.msi" )
$install = Start-Process -FilePath msiexec -ArgumentList "/i $home\desktop\agent.msi /qn ADDLOCAL=ALL /l*v `"C:\.armor\dsa_install.log`"" -Wait -PassThru
rm $home\desktop\agent.msi

#endregion




########
# CPU  #
########\.armor
#region CPU
#Get CPU Count
gwmi win32_processor | Measure-Object -Property NumberOfLogicalProcessors,NumberOfCores -Sum

# Check Hyper threading and get total CPU count
[object[]]$procs = gwmi win32_processor ;$props = $procs| Measure-Object -Property NumberOfLogicalProcessors,NumberOfCores -Sum;if($props[0].Sum -gt $props[1].Sum){Write-Host -ForegroundColor Green "Hyperthreading Enabled"}else{Write-Host -ForegroundColor Red "Hyperthreading Not Enabled"};New-Object psobject @{Cores = $procs.count; LogicalCPUs = $props[0].sum;PhysicalCPUs=$props[1].sum}

(Get-Counter '\Process(*)\% Processor Time').Countersamples | Where cookedvalue -gt 3 | Sort cookedvalue -Desc | ft -a instancename, @{Name='CPU %';Expr={[Math]::Round($_.CookedValue)}}

#endregion

########
# Disk #
########
#region Disks
#query Disk Utilizaion by Directory(Function):
 $ErrorActionPreference = "SilentlyContinue"; function audit ($path){"" + "{0:N0}" -f ((gci -force $path| Measure-Object -Sum Length).sum / 1MB) + "`t`t`t`t" + $path; foreach($fldr in (gci -force $path | ?{$_.PSIsContainer} | select-object fullname)){"" + "{0:N0}" -f ((gci -force $fldr.FullName -r | Measure-Object -Sum Length).sum / 1MB) + "`t`t`t`t" + $fldr.FullName }}
#Modified version
function audit($path){$ErrorActionPreference="SilentlyContinue";""+"{0:N0}"-f((gci -force $path|Measure-Object -Sum Length).sum /1MB)+"`t`t`t`t"+$path;$flders=gci -force $path|?{$_.PSIsContainer};$ctr=0;foreach($fldr in $flders){$ctr++;Write-Progress -Activity "Querying Folders" -Status "$ctr of $($flders.count)" -PercentComplete (($ctr/$flders.count)*100);""+"{0:N0}"-f((gci -force $fldr.FullName -r|Measure-Object -Sum Length).sum/1MB)+"`t`t`t`t"+$fldr.FullName}}
#then:
audit C:\path\to\audit


#create and format new vhd
New-VHD -Path c:\path\to\newdrive.vhdx -Dynamic -SizeBytes 5GB |`
    Mount-VHD -Passthru |`
    New-Partition -AssignDriveLetter -UseMaximumSize |`
    Format-Volume -FileSystem NTFS -Confirm:$false -Force



#wmi List all disk drives with Drive Size and Free Space
gwmi win32_logicaldisk | where{$_.drivetype -eq '3'} |ft deviceid,volumename,@{n="SizeGB";e={[math]::Round($_.size/1GB)}},@{n="Free Space (GB)";e={[math]::Round($_.Freespace/1GB)}}

#list drive, name, size, SCSI, and Serial Number
#OLD!!#$disks=gwmi win32_diskdrive|select __path,@{n="SCSI_Id";e={[string]$([int]$_.scsiport)+":"+$_.scsitargetid}},serialnumber;function match-phystological($physical,$logical){$physmatch = $physical|where{$_.__path -eq $((gwmi win32_diskdrivetodiskpartition|where{$_.dependent -eq $((gwmi win32_logicaldisktopartition|where{$_.dependent -eq $($logical.__PATH)}).antecedent)}).antecedent)};return $physmatch};$resultshash=New-Object System.Collections.ArrayList;gwmi win32_logicaldisk|where{$_.drivetype -eq '3'}|ForEach-Object{$objtmp = ""| select Drive,Name,SCSI-ID,SizeGB,FreeGB,Serial#;$objtmp.Drive = $_.deviceid;$objtmp.Name = $_.volumename;$objtmp.'SCSI-ID' = (match-phystological $disks $_).SCSI_Id;$objtmp.SizeGB = [Math]::Round($_.size/1GB);$objtmp.FreeGB=[Math]::Round($_.FreeSpace/1GB);$objtmp.'Serial#'=(match-phystological $disks $_).serialnumber;$resultshash.Add($objtmp)|Out-Null};$resultshash|ft -a
$c=$env:COMPUTERNAME;$disks=gwmi win32_diskdrive -Comp $c|select __path,@{n="SCSI_Id";e={[string]$([int]$_.scsiport)+":"+$_.scsitargetid}},serialnumber,Type;function match($p,$l,$c){$l2p=gwmi win32_logicaldisktopartition -comp $c|?{$_.dependent -eq $l.__PATH};$d2p=gwmi win32_diskdrivetodiskpartition -comp $c|?{$_.dependent -eq $l2p.antecedent};$tmp=Get-WmiObject Win32_DiskPartition -comp $c|?{$_.__PATH -eq $l2p.Antecedent};$t=switch -Regex ($tmp.type){'^GPT'{'GPT'};'^Ins'{'MBR'};default{'unavailable'}}$p=$p|?{$_.__path -eq $d2p.antecedent};$p.Type=$t;$p};gwmi win32_logicaldisk -comp $c |?{$_.drivetype -eq '3'}|%{$d = match $disks $_ $c;New-Object psobject -Property @{Computer=$c;Drive=$_.deviceid;Name=$_.volumename;SCSIID=$d.SCSI_Id;SizeGB=[Math]::Round($_.size/1GB);FreeGB=[Math]::Round($_.FreeSpace/1GB);Serial=$d.serialnumber;Type=$d.Type}}|ft -a Computer,Name,Drive,Type,SCSIID,FreeGB,SizeGB,Serial

#Get Disk info for multiple computers:
#Get List of computers:
$computers = Get-Content c:\Computers.txt
#Run Function
function match($p,$l,$c){$l2p=gwmi win32_logicaldisktopartition -comp $c|?{$_.dependent -eq $l.__PATH};$d2p=gwmi win32_diskdrivetodiskpartition -comp $c|?{$_.dependent -eq $l2p.antecedent};$tmp=Get-WmiObject Win32_DiskPartition -comp $c|?{$_.__PATH -eq $l2p.Antecedent};$t=switch -Regex ($tmp.type){'^GPT'{'GPT'};'^Ins'{'MBR'};default{'unavailable'}}$p=$p|?{$_.__path -eq $d2p.antecedent};$p.Type=$t;$p};
#Get Results
$r=foreach($c in $computers){$disks=gwmi win32_diskdrive -Comp $c|select __path,@{n="SCSI_Id";e={[string]$([int]$_.scsiport)+":"+$_.scsitargetid}},serialnumber,Type;gwmi win32_logicaldisk -comp $c |?{$_.drivetype -eq '3'}|%{$d = match $disks $_ $c;New-Object psobject -Property @{Computer=$c;Drive=$_.deviceid;Name=$_.volumename;SCSIID=$d.SCSI_Id;SizeGB=[Math]::Round($_.size/1GB);FreeGB=[Math]::Round($_.FreeSpace/1GB);Serial=$d.serialnumber;Type=$d.Type}}};$r|ft Computer,Name,Drive,Type,SCSIID,FreeGB,SizeGB,Serial
#Optional - export results or whatever.
$r|select Computer,Name,Drive,Type,SCSIID,FreeGB,SizeGB,Serial | Export-Csv $home\desktop\diskaudit.csv -NoTypeInformation


#Rscan after adding new disks
Get-Disk | Update-Disk #rescans disks
#Show Disks that can be expanded
Get-Partition | where{$_.DriveLetter -match "^[A-Z]{1}$"} | select Driveletter,@{n='SizeGB';e={[math]::Round($_.size/1GB)}},@{n="MaxSizeGB";e={[math]::Round($(Get-PartitionSupportedSize -DriveLetter $_.driveletter).sizemax/1GB)}} |where {$_.SizeGB -lt $_.MaxSizeGB}|ft -auto
#expand disks that can be expanded
Get-Partition | where{$_.DriveLetter -match "^[A-Z]{1}$"} | select Driveletter,@{n='SizeGB';e={[math]::Round($_.size/1GB)}},@{n="MaxSizeGB";e={[math]::Round($(Get-PartitionSupportedSize -DriveLetter $_.driveletter).sizemax/1GB)}} | foreach{if($_.SizeGB -lt $_.MaxSizeGB){Resize-Partition -DriveLetter $_.driveletter -Size $(Get-PartitionSupportedSize -DriveLetter $_.DriveLetter).sizemax}}

#configure  new disks
Get-Disk | Where partitionstyle -eq 'raw' | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "New Disk" -Confirm:$false


#Resize Disk
Get-Disk | Update-Disk #reescans disks
Get-Partition  -DriveLetter A
$maxsize = (Get-PartitionSupportedSize -DriveLetter E).sizemax
Resize-Partition -DriveLetter E -Size $maxsize
# or

#Change CD drive letter
$drv = Get-WmiObject win32_volume -filter 'DriveLetter = "K:"'
$drv.DriveLetter = "Z:"
$drv.Put() | out-null

Get-Disk -Number 2 | New-Partition -UseMaximumSize -DriveLetter E | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data1" -Confirm:$False 
Get-Disk -Number 3 | New-Partition -UseMaximumSize -DriveLetter F | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data2" -Confirm:$False 
 


###### DISKPART #######
#start diskpart
diskpart

#List All disks
list disk

#Select a particular disk
select disk X

#get details of disk
attr disk

#clear read-only from a disk
attributes disk clear readonly

#list SAN
san

#change SAN Policy(options are onlineall, offlineall, offlineshared, offlineinternal)
san policy=onlineall

#endregion

############
# Eventlog #
############
#region Eventlogs
#audit users who logged in
#Deprecated# Get-EventLog -log system | where {$_.eventid –eq '7001'} | ft TimeGenerated,@{n="Username"; e={(New-Object System.Security.Principal.SecurityIdentifier ($_.ReplacementStrings[1])).Translate( [System.Security.Principal.NTAccount]).value}}
Get-WinEvent  -FilterHashtable @{Logname='System';id=@('7001','7002')<#7002 for logoff notifications#>} -MaxEvents 25 |ft MachineName,TimeCreated,@{n="Username"; e={([System.Security.Principal.SecurityIdentifier]($_.properties[1].value)).Translate( [System.Security.Principal.NTAccount]).value}},message

#find unexpected reboots
Get-WinEvent -FilterHashtable @{Logname='System';id='6008'} -MaxEvents 10 |ft MachineName,TimeCreated,Message

#check who installed an application
Get-WinEvent -FilterHashtable @{LogName='Application';id=11707;ProviderName='MsiInstaller'} -ErrorAction SilentlyContinue| select Timecreated,@{n='User';e={(New-Object System.Security.Principal.SecurityIdentifier($_.userid.value)).translate([System.Security.Principal.NTAccount]) | select -ExpandProperty Value}},Message

#get username from SID
$sid = "S-1-5-21-2146980116-2859609073-3986486088-1003"
(New-Object System.Security.Principal.SecurityIdentifier ($sid)).Translate( [System.Security.Principal.NTAccount]).value

#Determine who last rebooted server:
#Deprecated# Get-EventLog -log system | where {$_.eventid –eq '1074'} | ft machinename, username, timegenerated –autosize
Get-WinEvent -FilterHashtable @{Logname='System';ID='1074'} -MaxEvents 25 | ft Machinename,timecreated,@{n='Username';e={$_.properties[6].value}},@{n='Reason';e={$_.properties[2].value}}
#server2008r2
Get-WinEvent -FilterHashtable @{Logname='System';ID='1074'} -MaxEvents 15 | ft Machinename,timecreated,@{n='Username';e={$_.properties[-2].value}},@{n='Reason';e={$_.properties[2].value}}


#Find the last windows updates installed
Get-WinEvent -LogName Setup -MaxEvents 15 | Format-Table Machinename,Timecreated,Message -A -Wr

#find eventlog cleared events
Get-WinEvent -FilterHashtable @{logname='security','system';id=@(104,1102)} -MaxEvents 2|ft -a -wr MachineName,Logname,TimeCreated,@{n='UserName';e={$sid = if($_.logname -eq 'System'){$_.userid.value}else{$_.Properties.value.value};(New-Object System.Security.Principal.SecurityIdentifier($sid)).translate([System.Security.Principal.NTAccount])}},Message







#endregion

#################
# Miscellaneous #
#################
#region Uncategorized
#get typenames
$object.PSTypenames

#clear typenames
$object.PSTypeNames.Clear()

#get/set Admin Filter Token Policy
#Get(0=enabled,1=disabled)
gp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" |ft LocalAccountTokenFilterPolicy
#set
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -name LocalAccountTokenFilterPolicy -value 0 -PropertyType 'DWord' -Force

#get SQL version
try{Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\setup' -ErrorAction Stop |ft PatchLevel,@{n='VersionName';e={switch -Regex($_.version){'^14\.' {"SQL Server 2017"};'^13\.'{"SQL Server 2016"};'^12\.'{"SQL Server 2014"};'^11\.'{"SQL Server 2012"};'^10\.5'{"SQL Server 2008 R2"};'^10\.0'{"SQL Server 2008"}}}},Edition}catch{Write-Warning "No SQL Server Instances Found"}

@{n='VersionName';e={switch -Regex($_.patchlevel){'^14\.' {"SQL Server 2017"};'^13\.'{"SQL Server 2016"};'^12\.'{"SQL Server 2014"};'^11\.'{"SQL Server 2012"};'^10\.5'{"SQL Server 2008 R2"};'^10\.0'{"SQL Server 2008"}}}}

#or
sqlcmd -Q "select @@version;"

#Tell PS to utilize .NET 4
$content = @'
<?xml version="1.0"?> 
<configuration> 
<startup useLegacyV2RuntimeActivationPolicy="true"> 
<supportedRuntime version="v4.0.30319"/> 
<supportedRuntime version="v2.0.50727"/> 
</startup> 
</configuration>
'@
Set-Content -Path "$pshome\powershell.exe.config" -Value $content -Force


#Get UUID
get-wmiobject Win32_ComputerSystemProduct  | Select-Object -ExpandProperty UUID


#Return Code of a command
(Get-Command  Connect-WSus).definition


###Get application by CLSID or APPid
Function Get-Appbyid([string[]]$appid,[string[]]$clsid){
$ids = @()
    switch($true)
    {
        $PSBoundParameters.ContainsKey('appid'){foreach($aid in $appid){ $ids += '{' + $aid + '}'}}
        $PSBoundParameters.ContainsKey('clsid'){foreach($cid in $clsid){$cid = '{'+$cid+'}';$ids += (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$cid" -ErrorAction SilentlyContinue).Appid}}
        Default{$appid = Read-Host -Prompt "Please provide AppID(s)";foreach($aid in $appid){ $ids += '{' + $aid + '}'}}
    }
    foreach($id in $ids)
    {
        Get-ItemProperty "HKLM:\SOFTWARE\Classes\AppID\$id" -ErrorAction SilentlyContinue|select @{n='Appname';e={$_.'(default)'}},@{n='AppID';e={$_.pschildname}}
    }
}

Function Encode-Command([string]$Command){
if(!$Command){$command = Read-Host -Prompt "Enter Command to Encode"}
$bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
[Convert]::ToBase64String($bytes)
}#Encode-Command

Function Decode-Command([string]$command){
if(!$Command){$command = Read-Host -Prompt "Enter Command to Encode"}
[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($command))
}


#endregion

##################
# NETSH Commands #
##################
#region Netsh Commands
#Add IP Address
netsh int ipv4 add address "Public" 134.0.76.57 255.255.252.0 skipassource=true
#remove ip
netsh int ipv4 delete address name="NAME_OF_LAN_INTERFACE" addr="IP_Address"

#clear ARP Cache
netsh int ip del arpcache

#show skipassource
netsh in ip show ipaddresses level=verb

#show nexthop
netsh interface ip show destinationcache

#show interfaces
netsh int ipv4 show interfaces
#after running, get specific interface info by opening upspecific interface by index#
netsh int ipv4 show interfaces interface=12

#view MTU Size:
netsh int ipv4 sh subinterface

#change MTU 
netsh interface ipv4 set subinterface "Local Area Connection" mtu=nnnn store=persistent

#show passive port ranges
"tcp","udp"|foreach{netsh int ipv4 sh dyna $_}

#set passive port ranges
netsh int ipv4 set dynamicport tcp start=5000 num=1000

#check offload
netsh int tcp show global | Select-String 'Chimney offload state','netdma','Receive-Side Scaling'
netsh int tcp show chimneystats
netsh int tcp show netdmastats
netsh int tcp show chimneyports
#endregion

#######################
# IIS Troubleshooting #
#######################
#region IIS
#import IIS PS Module first
Import-Module webadministration

#find a site by IP or URL
ls IIS:\Sites |where {$_.bindings.collection -match "IP_addr or URI"}

#list only started sites
ls IIS:\Sites |where {$_.state -eq 'started'}

#stop all sites
ls IIS:\Sites |foreach{$_.Stop()}

#start all sites
ls IIS:\Sites |foreach{$_.Start()}

#get apppool for a site
ls iis:\appools

#filter sites with SSL Bindings
ls IIS:\SslBindings

#list certs matching string
ls Cert:\LocalMachine -Recurse | where {$_.subjectname.name -match "m3information"}

####change cert friendlyname:
#set variable:
$cert = ls Cert:\LocalMachine -Recurse | where {$_.subjectname.name -match "spellingb" -and $_.notafter -match "2019"}
$cert.FriendlyName = "star.spellingb.tech"


#list all sites with their certificate bindings

#list all sites using a particular certificate:
#identify cert thumbprint you need to match to a site:
ls Cert:\LocalMachine -Recurse | fl FriendlyName,@{n='Expiration';e={$_.notafter.tostring("MM-dd-yyyy")}},Thumbprint,@{n='Subject';e={$_.subjectname.name}}


ls IIS:\SslBindings | where {$_.thumbprint -match "D18F3D5D608CA74BE48BFC5D2A9B45FA9E85B1FC"}

$sslbindings = ls IIS:\SslBindings | select ipaddress,port,@{n='Sites';e={$_.sites.value}},@{n='Certificate';e={$cert = $_;ls Cert:\LocalMachine\$($_.store)|where {$_.thumbprint -eq $cert.thumbprint}}}


ls Cert:\LocalMachine\$($sslsites[0].store)


#endregion

######################
# AD Troubleshooting #
######################
#region Active Directory Replication
#pull replication
repadmin /syncall

#query fsmo roles
netdom /query fsmo

#push Replication
repadmin /syncall /APed

#show replication summary
repadmin /replsum

#show replication latency
repadmin /showvector /latency "DC=clinithink-fh,DC=local"

#show replications
repadmin /showreps
repadmin /showrepl * /csv | ConvertFrom-Csv | Out-GridView
Get-ADReplicationPartnerMetadata -Target "dfwdc01","dfw-dc-01" -Partition * | ft -auto -wrap Server,partition,ConsecutiveReplicationFailures,lastreplicationsuccess,lastreplicationresult

#make backup
ntdsutil
    ntdsutil:>activate instance ntds
    ntdsutil:>ifm
    ifm:>create full c:\path\to\file\ifm

#running Replication Diagnostics
dcdiag
dcdiag /test:dns /v
dcdiag /fix 
dcdiag /test:replications
dcdiag /s:domaincontrollername
nltest /dclist:tokenextest.local
nltest /dsregdns
nltest /dsgetdc:zollhosted.com /gtimeserv /force
ipconfig -registerdns


#check netlogon and sysvol share(or just list shares)
net share

#transfer fsmo roles
ntdsutil
roles
connections
connect to server SERVERNAME
q
transfer NAME_OF_ROLE

#clean metadata
 NTDSUTIL 
 METADATA CLEANUP
 connections
 connect to server SERVERNAME
 q
 select operation target
 list domains
 select domain NUMBER
 list sites
 select site NUMBER
 list servers in site
 select server NUMBER #select the server you would like to clean up
 q
 remove selected server

 #then remove cname record of server from _msdcs.domain_name

 #### Client to AD T/S
 # Netdom:
 netdom /query trust

 netdom query pdc

 netdom query fsmo

 #query AD Controller for domain
 netdom verify DFWHQ-AD03 /domain:corp.firehost.net

 #endregion


##########################
#w32time configurations  #
##########################
#region w32time commands
#query time settings
w32tm /query /configuration

#query sync server
w32tm /query /source

#resync
w32tm /resync /rediscover /nowait

#set for domain time sync
w32tm /config /syncfromflags:domhier /update /reliable:yes

#configure for Armor
w32tm /config /syncfromflags:manual /manualpeerlist:"ntp.armor.com" /update

#configure for time pool
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org" /update

#Display the current time zone settings.
w32tm /tz

#general or self explanitory
w32tm /monitor

w32tm /resync

#stripchart monitoring:
w32tm /stripchart /computer:(target computer or domain)
#endregion

#######################
# Failover Clustering #
#######################
#region WFC
#Get cluster status
Get-ClusterGroup

#failover all clustergroups
Get-ClusterNode CURRENT_CLUSTER_OWNER | Get-ClusterGroup | Move-ClusterGroup -Node NEW_CLUSTER_OWNER -Wait 0

get-clusterresource

get-clusterparameter

Get-Cluster | Get-ClusterResource | where {$_.resourcetype -match "ip address"} | Get-ClusterParameter 

#get file share witness
Get-ClusterResource | where{$_.resourcetype -eq 'file share witness'}|Get-ClusterParameter |ft -A


# find Failover Events from clusterlog:
$clusterlogs = Get-ClusterLog -Node $env:COMPUTERNAME -Destination $env:userprofile\Desktop -UseLocalTime 
$pattern =  "move of group.+from.+to.+ of type"
$patternmatch = Get-Content $clusterlogs.FullName | Select-String -Pattern $pattern

#endregion



##################
# Windows Backup #
##################
#region vssadmin

# list writers
vssadmin list writers

#list vss writers and output to object
$ErrorActionPreference = 'stop'
$objwriter = @()
$writers = vssadmin list writers | Where-Object { $_ -and ( $_ -match ':' ) } | ForEach-Object { $_.trim('') }
$property_names = $writers | Where-Object { $_  -and ( $_ -match ':' ) } | ForEach-Object { $_.split( ':' )[0].trim( '' ) } | Select-Object -Unique
$writers | Where-Object { $_ -match $property_names[0] } | ForEach-Object {
    $writername = $_
    $propindex = $writers.IndexOf( $writername )
    [string[]]$writer = $writers[$propindex..( $propindex + $property_names.Count )]
        $temphash = @{}
        $writers[$propindex..( $propindex + ( $property_names.Count - 1) )] | ForEach-Object {
            $prop = $_.split(':')
            $temphash.Add( $prop[0], $prop[1].trim('').Trim("{'}" ) )
        }
    $objwriter += New-Object psobject -Property $temphash
}
$objwriter | ft $property_names
 

#list shadows
vssadmin list shadwos

#list shadows as objects



#function to do this stuff
Function cmdtoobj {
    param(
        [Parameter(ValueFromPipeline)]$InputObject,[string]$delimiter = '\s'
    )
    begin
    {
        $output = @()

    }
    process
    {
        $properties = $InputObject | Where-Object { $_ -and ( $_ -match $delimiter ) } | ForEach-Object { $_.trim( '' ).split( $delimiter )[0]} | Select-Object -Unique

        $InputObject | Where-Object { $_ -match $properties[0] } | ForEach-Object {
            $tmphash = @{}
            $writername = $_
            $property_index = $InputObject.indexof( $writername )
            $InputObject[$property_index..( $property_index + ( $properties.count - 1 ) )] | ForEach-Object {
                $prop = $_.split( $delimiter ) | ForEach-Object { $_.trim( '' ).trim( "{'}" ) }
                $tmphash.add( $prop[0], $prop[1] )
            }
            $output += New-Object psobject -Property $tmphash
            Remove-Variable tmphash
        }
        return ( $output|select $properties )
    }
}


#endregion



##########
# windbg #
##########
#set symbol path:
.sympath srv*c:\Websymbols*http://msdl.microsoft.com/download/symbols;
#reload
.reload /f

#verify symbols loaded
lmvm sqlservr

#load the dump

#analyze
! analyze -v


# look at threads
~*kL 20




#powershell v2 correcting skipassource flag
$primaryIP = "10.0.0.2"
$primarySNM = "255.0.0.0"
$isIpValid = [System.Net.IPAddress]::tryparse([string]$primaryIP, [ref]"1.1.1.1")
$netNAC = Get-WmiObject Win32_NetworkAdapterConfiguration |where {$_.ipaddress -notmatch "10.*" -and $_.ipaddress -notmatch "100.*" -and $_.ipaddress -ne $null} 
$netInterface = (gwmi win32_networkadapter -Filter "DeviceID='$($netNAC.index)'").netconnectionid
$ips = @()
0..($netNAC.IPAddress.count - 1) | Where-Object {$netNAC.IPAddress[$_].ToString() -ne $primaryIP -and $netNAC.IPAddress[$_].ToString() -like "*.*.*.*"} | ForEach-Object {


        $temp = New-Object PSObject -Property @{

            IPAddress = $netNAC.IPAddress[$_].ToString()

            IPSubnet = $netNAC.IPSubnet[$_].ToString()

        }

        $IPs += $temp

    }
netsh int ipv4 delete address "$netInterface" $primaryIP
netsh int ipv4 add address "$netInterface" $primaryIP $primarySNM skipassource=false
foreach ($ip in $IPs) {
      Invoke-Expression "netsh int ipv4 delete address `"$interface`" $($ip.IPAddress)"
      Invoke-Expression "netsh int ipv4 add address `"$interface`" $($ip.IPAddress) $($ip.IPSubnet) skipassource`=true"
    }


#winrm
#Browse to Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service
$computers = 'localhost'
$computers | ForEach-Object { ([wmiclass]"\\$_\root\cimv2:win32_process").Create('powershell Enable-PSRemoting -Force') }

$cn = 'localhost'
([wmiclass]"\\$cn\root\cimv2:win32_process").Create('powershell Enable-PSRemoting -Force')

([wmiclass]"\\localhost\root\cimv2:win32_process").Create('powershell netstat -ano | ')

Enable-PSRemoting –force
Set-Service WinRM -StartMode Automatic
Set-Item WSMan:localhost\client\trustedhosts -value '*' -force
Get-Item WSMan:\localhost\Client\TrustedHosts
& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -m
logoff
#winrm port: 5986




######Auto Lab Post-Provisioning ######

# add dvd drive and Mount ISO
Add-VMDvdDrive s1,s2 -Path C:\AutoLab\Resources\SQL\2012\SQLFULL_ENU.iso -Passthru

Mount-VHD -Path C:\AutoLab\VMVirtualHardDisks\Cli1.VHDX

Copy-Item -Path C:\AutoLab\Resources\SQL\SSMS-Setup-ENU.exe -Destination 




#### Add Local Repo #######
$repo = @{
    Name = 'RepoName'
    SourceLocation = $Path
    PublishLocation = $Path
    InstallationPolicy = 'Trusted'
    ScriptSourceLocation = $path
    ScriptPublishLocation = $path
}
Register-PSRepository @repo


$modpath = 'C:\Users\bspell\Google Drive\GITHUB\Repository\Packages'
$scrpath = 'C:\Users\bspell\Google Drive\GITHUB\Repository\PSScripts'

$repo = @{
    Name = 'BSLocal'
    SourceLocation = $modpath
    PublishLocation = $modpath
    InstallationPolicy = 'Trusted'
    ScriptSourceLocation = $modpath
    ScriptPublishLocation = $modpath
}
