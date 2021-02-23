﻿[CmdletBinding()] 
    Param (
    [switch]$serverinfo,
    [switch]$getuptime,
    [switch]$pendingreboot,
    [switch]$avcheck,
    [switch]$protocolcheck,
    [switch]$ciphercheck,
    [switch]$installedsoftware,
    [switch]$patchcheck,
    [switch]$showarmorservices
    )

Begin {
    Function Server-Info
    {
        $hostname = [System.Net.Dns]::GetHostName()
        $osinfo = $OS = Get-CimInstance Win32_OperatingSystem | select -ExpandProperty Caption;$OSSP = (Get-CimInstance Win32_OperatingSystem | select -ExpandProperty ServicePackMajorVersion);$OSArch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        $ipinfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet* | select InterfaceAlias,IPAddress | ft -AutoSize
        $domain = (Get-CimInstance Win32_ComputerSystem).Domain
        $dns = Get-DnsClientServerAddress -InterfaceAlias "Ethernet*"  | select -ExpandProperty ServerAddresses | Where-Object {$_ -notlike "*:*"}
        $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB),2))}
        $cpuinfo = Get-CimInstance –class Win32_processor | ft DeviceID,NumberOfCores,NumberOfLogicalProcessors
        Function drive-info
        {
            $driveinfo = $c=$env:COMPUTERNAME
            $disks=gwmi win32_diskdrive -Comp $c|select __path,@{n="SCSI_Id";e={[string]$([int]$_.scsiport)+":"+$_.scsitargetid}},serialnumber,Type
            function match($p,$l,$c){$l2p=gwmi win32_logicaldisktopartition -comp $c|?{$_.dependent -eq $l.__PATH}
            $d2p=gwmi win32_diskdrivetodiskpartition -comp $c|?{$_.dependent -eq $l2p.antecedent}
            $tmp=Get-WmiObject Win32_DiskPartition -comp $c|?{$_.__PATH -eq $l2p.Antecedent}
            $t=switch -Regex ($tmp.type){'^GPT'{'GPT'};'^Ins'{'MBR'}
            default{'unavailable'}}$p=$p|?{$_.__path -eq $d2p.antecedent};$p.Type=$t;$p}
            gwmi win32_logicaldisk -comp $c |?{$_.drivetype -eq '3'}|%{$d = match $disks $_ $c
            New-Object psobject -Property @{Computer=$c;Drive=$_.deviceid;Name=$_.volumename;SCSIID=$d.SCSI_Id;SizeGB=[Math]::Round($_.size/1GB)
            FreeGB=[Math]::Round($_.FreeSpace/1GB);Serial=$d.serialnumber;Type=$d.Type}}|ft -a Computer,Name,Drive,Type,SCSIID,FreeGB,SizeGB,Serial
        }
        $drive = drive-info
        Write-Output "Hostname: $hostname"
        " "
        Write-Output "OS: $osinfo"
        " "
        Write-Output "IP Information:"$ipinfo 
        " "
        Write-Output "DNS Server IPs:"$dns
        " "
        Write-Output "CPU Information"$cpuinfo
        Write-Output "Total RAM: $memory GB"
        " "
        Write-Output "Drive Information:"$drive
        
        }
    Function Get-Uptime
        {
        $os = Get-WmiObject win32_operatingsystem
        $uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
        $Display = "" + $Uptime.Days + " days, " + $Uptime.Hours + " hours, " + $Uptime.Minutes + " minutes" 
        $lastboottime = Get-CimInstance CIM_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
        Write-Output "System Uptime:"
        Write-Output $Display
        Write-Output "Last Rebooted:"$lastboottime
        }
    function PendingReboot
        {
        Write-Output "Pending Reboot" 
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
    Function Protocolcheck
        {
        Write-Output "Protocols" w
        $ErrorActionPreference = "SilentlyContinue"
        $OScheck = Get-CimInstance Win32_OperatingSystem | select -ExpandProperty Caption | Select-String -Pattern '20\d\d' | ForEach-Object { $_.Matches.Value }
        $SSL2 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' | select -ExpandProperty Enabled
        $SSL3 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' | select -ExpandProperty Enabled
        $tls10 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' | select -ExpandProperty Enabled
        $tls11 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' | select -ExpandProperty Enabled
        $tls12 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' | select -ExpandProperty Enabled
        If ($tls10 -eq 0 -or $tls10 -eq $null){Write-Output "TLS 1.0 is Disabled"}Else{Write-Output "TLS 1.0 is Enabled"}
        If ($OScheck -gt 2012)
        {
        If ($tls11 -eq 0) {Write-Output "TLS 1.1 is Disabled"}Else{Write-Output "TLS 1.1 is Enabled"}
        If ($tls12 -eq 0) {Write-Output "TLS 1.2 is Disabled"}Else{Write-Output "TLS 1.2 is Enabled"}
        }Else{
        If ($tls11 -eq 0 -eq $null) {Write-Output "TLS 1.1 is Disabled"}Else{Write-Output "TLS 1.1 is Enabled"}
        If ($tls12 -eq 0 -eq $null) {Write-Output "TLS 1.2 is Disabled"}Else{Write-Output "TLS 1.2 is Enabled"}
        }}
    function CipherCheck {
        Write-Output "Ciphers"  
        $ciphercheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002\ -Name Functions | select -ExpandProperty Functions 
        $ciphercheck2 = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003\ -Name Functions | select -ExpandProperty Functions
        $reply = Read-Host -Prompt "Do you wish to view the Ciphers?[y/n]"
        ""
        If ( $reply -like "y" ) 
        {Write-Output 
        $ciphercheck 
        $ciphercheck2}
        Else{Write-Output "Skipping Cipher Check"}
        }
    function AV-Check 
        {Write-Output "Installed Antivirus Software"  
        $ErrorActionPreference = "SilentlyContinue"
        $antivirus = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -match "avast|avg|bitdefender|clamav|crowdstrike|endpoint protection|eset|internet security|kapersky|mcafee|norton|smart security|sophos|symantec|trend|virus" } | Select-Object -Property DisplayName | Select -ExpandProperty DisplayName
        If ($antivirus -eq $null)
        {Write-Output "No Antivirus Installed"}Else{$antivirus}
        }
    Function Patch-Check
        {
        $patchcheck = Get-HotFix | Select-Object -Property Description,HotFixID,InstalledOn | Select-Object -Last 5 | Sort-Object -Descending | Format-Table
        Write-Output "Most Recent Patches Installed:"$patchcheck
        } 
    Function Installed-Software 
        {Write-Output "Software Check"
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
        Write-Output ""
        #Write-Output "Instance: $i"
        Write-Output "Product: $product"
        Write-Output "Edition: $edition"
        Write-Output "Version: $version"
        Write-Output ""
        }
        }Else{
        Write-Output "SQL Software not installed"
        }
        ""
        $iis = (Get-WindowsFeature web-server).InstallState
        if ($iis -eq "Installed") {Write-Output "IIS is Installed"} Else {Write-Output "IIS is NOT Installed"}
    Function Show-Armorservices
        { 
        Function Agent-Version
        {
        Write-Host "Armor Agent Information" -ForegroundColor Yellow
        $agentversion = C:\.armor\opt\armor.exe --v
        $agentversion = $agentversion.split(" ")[2]
        If ($agentversion -eq $null){Write-Host "Armor Agent is not installed"}Else{Write-Host "Armor Agent Version: $agentversion"}
        }
        $ErrorActionPreference = "SilentlyContinue"
        
        Function Agent-Info
        {
        $ErrorActionPreference = 'silentlycontinue'
        $armoragent = gsv armor-agent | select -ExpandProperty Status
        If ($armoragent -eq $null) {Write-Host "Armor Agent Status: Not Installed"}Else{Write-Host "Armor Agent Status: $armoragent"}
        
        }
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
        
        Function Armor-Services
        {Write-Host "Armor Subagent Service Status" -ForegroundColor Yellow
        $services = @{}
        $servicenames = @('AMSP','ds_agent','ds_monitor','ds_notifier','ds_agent', 'Armor-Filebeat', 'Armor-Winlogbeat','QualysAgent', 'PanoptaAgent')
        Foreach ($servicename in $servicenames ) {
        try {
        $servicestatus = gsv $servicename -ErrorAction Stop | select -ExpandProperty status
        #$servicedisplay = gsv $servicename -ErrorAction Stop | select -ExpandProperty DisplayName
        } catch {
        $servicestatus = 'Not Installed'        
        }
        $services.Add($servicename , $servicestatus)
        }
        New-Object psobject -Property $services | Out-Default
        }
        $ErrorActionPreference = "SilentlyContinue"
        }
        
        {
        $showsubagents = show-subagents
        $agentversion = Agent-Version
        $agentinfo = Agent-Info
        $armorservices = Armor-Services
        
        Write-Output "$agentinfo"
        Write-Output "$agentversion"
        Write-Output "$showsubagents"
        Write-Output "$armorservices"
        }        
        }

Process
        {
        If ($serverinfo){server-info}
        If ($getuptime){Get-Uptime}
        If ($pendingreboot){PendingReboot}
        If ($avcheck){AV-Check}
        If ($patchcheck){Patch-Check}
        If ($protocolcheck){Protocolcheck}
        If ($ciphercheck){CipherCheck}
        If ($installedsoftware){Installed-Software}
        If ($showarmorservices){Show-Armorservices}
}