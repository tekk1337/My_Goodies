<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.Example
PS C:\Test Script> .\wininfo-v3.ps1 -serverinfo

This section will display the general server information (ie. Hostname, drive Information, CPU, Memory, etc.)
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes

#>

#Requires -Version 3.0
[CmdletBinding()] 
Param (
    # Get General Server Information (ie. Hostname, drive Information, CPU, Memory, etc.)
    [switch]
    $serverinfo,

    # Gets Server Uptime
    [switch]
    $getuptime,

    # Checks for pending Reboots
    [switch]
    $pendingreboot,

    #Checks for existing AV
    [switch]
    $avcheck,

    #Returns installed Software
    [switch]
    $installedsoftware,

    #Gets installed Patches
    [switch]
    $patchcheck,

    #Returns any non-default protocol settings
    [switch]
    $protocolcheck,

    #Returns any non-default Cipher Settings
    [switch]
    $ciphercheck,

    #returns Armor Subagents
    [switch]
    $showarmorservices,

    #Returns info of disks
    [switch]
    $Disks,

    #returns any unexpected Reboots.
    [switch]
    $unexpectedReboot
)

Begin {
    #Recommend change to 'Get-DriveInfo'
    #to do: 
    # Change gwmi to get-ciminstance
    # Change out all Aliases
    # Formatting
    Function drive-info {
        $c=$env:COMPUTERNAME
        $disks= gwmi win32_diskdrive -Comp $c|select __path,@{n="SCSI_Id";e={[string]$([int]$_.scsiport)+":"+$_.scsitargetid}},serialnumber,Type
        function match($p,$l,$c){$l2p=gwmi win32_logicaldisktopartition -comp $c|?{$_.dependent -eq $l.__PATH}
        $d2p=gwmi win32_diskdrivetodiskpartition -comp $c|?{$_.dependent -eq $l2p.antecedent}
        $tmp=Get-WmiObject Win32_DiskPartition -comp $c|?{$_.__PATH -eq $l2p.Antecedent}
        $t=switch -Regex ($tmp.type){'^GPT'{'GPT'};'^Ins'{'MBR'}
        default{'unavailable'}}$p=$p|?{$_.__path -eq $d2p.antecedent};$p.Type=$t;$p}

        $return = gwmi win32_logicaldisk -comp $c |?{$_.drivetype -eq '3'}|%{$d = match $disks $_ $c
        New-Object psobject -Property @{Computer=$c;Drive=$_.deviceid;Name=$_.volumename;SCSIID=$d.SCSI_Id;SizeGB=[Math]::Round($_.size/1GB)
        FreeGB=[Math]::Round($_.FreeSpace/1GB);Serial=$d.serialnumber;Type=$d.Type}}

        return  ($return|select Computer,Type,Drive,Name, FreeGB,SizeGB,SCSIID,Serial)
    }
    
    #recommend changing Server-Info to Get-ServerInfo
    Function Server-Info {
        $os = Get-CimInstance Win32_OperatingSystem
        $ips = Get-NetAdapter -Physical | Get-NetIPAddress -AddressFamily IPv4
        $drives = drive-info
        [string[]]$dns = Get-NetAdapter -Physical | 
            Get-DnsClientServerAddress -AddressFamily IPv4 |
                Where-Object { $_.ServerAddresses} | 
                    ForEach-Object { '{0}: {1}' -f $_.InterfaceAlias,($_.ServerAddresses -join ', ')
                    }
        $hostname = [System.Net.Dns]::GetHostName()
        $domain = (Get-CimInstance Win32_ComputerSystem).Domain
        $dns = Get-DnsClientServerAddress -InterfaceAlias "Ethernet*"  | select -ExpandProperty ServerAddresses | Where-Object {$_ -notlike "*:*"}
        $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | ForEach-Object {"{0} GB" -f ([math]::round(($_.Sum / 1GB)))}
        $phys = Get-CimInstance win32_processor
        $logical = $phys | Measure-Object -Property NumberOfLogicalProcessors,NumberOfCores -Sum

        New-Object psobject -Property ([ordered]@{
            Computer = $hostname
            OS = $os.Caption
            Domain = $domain
            IPAddresses = $ips.IPv4Address -join ', '
            DNS = $dns -join "`n`r"
            CPU = 'Sockets: {0}; CoresPerSocket: {2}; LogicalProcessors: {1}' -f ($phys|Measure-Object).Count, $logical[0].Sum, $logical[1].Sum
            Memory = $memory
            Disks = foreach($drive in $drives){"Drive: {0}; Type: {1};Location: {2}; Free/Total Storage: {3} GB /{4} GB`n`r" -f $drive.Drive, $drive.Type, $drive.SCSIID, $drive.FreeGB, $drive.SizeGB}
        })
    }#end Server-Info
    
    Function Get-Uptime
        <#.Example: PS C:\Test Script> .\wininfo-v3.ps1 -getuptime
        This section will show uptime for the server (ie. last reboot time and how long since last reboot)
        #>
        {
        $os = Get-WmiObject win32_operatingsystem
        $uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
        $Display = "" + $Uptime.Days + " days, " + $Uptime.Hours + " hours, " + $Uptime.Minutes + " minutes" 
        $lastboottime = Get-CimInstance CIM_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
        Write-Host "System Uptime" -ForegroundColor Yellow
        Write-Output "System Uptime:"
        Write-Output $Display
        Write-Output "Last Rebooted:"$lastboottime
        }
    function PendingReboot
        <#.Example: PS C:\Test Script> .\wininfo-v3.ps1 -pendingreboot
        This section will show if there are any pending reboot flags on the server
        #>
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
    Function Protocolcheck
        <#.Example: PS C:\Test Script> .\wininfo-v3.ps1 -protocolcheck
        This section will display which, if any, protocol suites are enabled (ie. TLS 1.2)
        #>
        {
        Write-Host "Protocols" -ForegroundColor Yellow
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
        Write-Host "Ciphers" -ForegroundColor Yellow
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
        {Write-Host "Installed Antivirus Software" -ForegroundColor Yellow  
        $ErrorActionPreference = "SilentlyContinue"
        $antivirus = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -match "avast|avg|bitdefender|clamav|crowdstrike|endpoint protection|eset|internet security|kapersky|mcafee|norton|smart security|sophos|symantec|trend|virus" } | Select-Object -Property DisplayName | Select -ExpandProperty DisplayName
        If ($antivirus -eq $null)
        {Write-Output "No Antivirus Installed" | Out-Default}Else{$antivirus | Out-Default}
        }
    Function Patch-Check
        {
        $patchcheck = Get-HotFix | Select-Object -Property Description,HotFixID,InstalledOn | Select-Object -Last 5 | Sort-Object -Descending | Format-Table
        Write-Host "Most Recent Patches Installed" -ForegroundColor Yellow
        Write-Output $patchcheck | Out-Default
        } 
    Function Installed-Software 
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
        }
     
    Function Agent-Version
        {
        $agentversion = C:\.armor\opt\armor.exe --v
        $agentversion = $agentversion.split(" ")[2]
        If ($agentversion -eq $null){Write-Host "Armor Agent is not installed"}Else{Write-Host "Armor Agent Version: $agentversion"}
        }
        $ErrorActionPreference = "SilentlyContinue"
        
    Function Agent-Info
        {
        Write-Host "Armor Agent Information" -ForegroundColor Yellow
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
    Function Show-Armorservices
        {
        $showarmorservices = Agent-Info;Agent-Version;show-subagents;Armor-Services
        }
}

Process{
    switch ( $true ) {
        $serverinfo { Server-Info }
        $getuptime { Get-Uptime }
        $pendingreboot { PendingReboot }
        $avcheck { AV-Check }
        $installedsoftware { Installed-Software }
        $patchcheck { Patch-Check }
        $protocolcheck { Protocolcheck }
        $ciphercheck { CipherCheck }
        $showarmorservices { Show-Armorservices }
        $Disks { drive-info }
        $unexpectedReboot {
            Get-WinEvent -FilterHashtable @{Logname='System';id='6008'} -MaxEvents 10 |Select-Object MachineName,TimeCreated,Message
        }
        default {
            getserverinfo
            getuptime
            avcheck
        }
    }
}