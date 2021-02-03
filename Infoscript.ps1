[CmdletBinding()]    
    Param (
    [switch]$serverinfo,
    [switch]$getuptime,
    [switch]$pendingreboot,
    [switch]$avcheck,
    [switch]$patchcheck,
    [switch]$armorservices,
    [switch]$showsubagents
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
    #function PendingReboot
    #{
    #    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
    #    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
    #    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
    #    try { 
    #    $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
    #    $status = $util.DetermineIfRebootPending()
    #    if(($status -ne $null) -and $status.RebootPending){
    #    return $true
    #    }
    #    }catch{}
    #    return $false
    #}
    #    $pendingreboot = PendingReboot
    #$rebootcheck = PendingReboot;If ($rebootcheck -eq "True"){Write-Output "Pending Reboot: True"}Else{Write-Output "Pending Reboot: False"}
    function AV-Check 
        {
        $ErrorActionPreference = "SilentlyContinue"
        $antivirus = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -match "trend|mcafee|eset|symantec|norton|bitdefender|sophos|kapersky|avast|avg|avg|clamav|virus|endpoint protection|smart security|internet security" } | Select-Object -Property DisplayName | Select -ExpandProperty DisplayName
        If ($antivirus -eq $null){Write-Output "Anvtivirus Installed: No Antivirus Found"}Else{Write-Output "Antivirus Installed: $antivirus"}}
    Function Patch-Check
        {
        $patchcheck = Get-HotFix | Select-Object -Property Description,HotFixID,InstalledOn | Select-Object -Last 5 | Sort-Object -Descending | Format-Table
        Write-Output "Most Recent Patches Installed:"$patchcheck
        } 
    Function Installed-Software 
        {
        $ErrorActionPreference = "SilentlyContinue"
        $iis = (Get-WindowsFeature web-server).InstallState
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
        }}}     }
    Function Armor-Services
        {Write-Output "Armor Subagent Service Status:"
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
    Function Agent-Info
        {
        $ErrorActionPreference = 'silentlycontinue'
        $armoragent = gsv armor-agent | select -ExpandProperty Status
        }
    Function show-subagents
        {Write-Output "Installed Subagents:"
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
        }

Process
{
    If ($serverinfo){server-info}
    If ($getuptime){Get-Uptime}
    #If ($pendingreboot){PendingReboot}
    If ($avcheck){AV-Check}
    If ($patchcheck){Patch-Check}
    If ($armorservices){Agent-Info;Armor-Services;show-subagents}
    #If ($showsubagents){show-subagents}
}
End
{


}