<#
.Synopsis
   Fully Uninstalls Trend Micro Deep Security Agent from a Windows Server and reinstall post-reboot.
.DESCRIPTION
   This Script is designed to uninstall the
#>

 
Param
(
    # Will Reboot the server after the installation completes
    [switch]
    $RebootAfterUninstall,
 
    #Path for the logfile. Default path will be the directory that you run the script.
    $Logfile = "$(gc env:computername)_DSAUninst.log",
 
    $DsaInstallDir = "$Env:ProgramFiles\Trend Micro\Deep Security Agent",
 
    # By default, debugging is enabled. set to '$false' to disable
    $EnableDebugLog = $true,
 
    # Sets the Expireation for the scheduled install. Default is 1 Day
    $taskexpirationdays = 1
)
 
Begin
{
    $ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
 
    #Priviledge Check
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    if((New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $False) {
        Write-Error("Administrators privilege is required!")
        Exit 5 
    }
 
    #Map HKEY_CLASSES_ROOT registry hive:
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
 
    # Functions
    # WriteLog: Write a log entry to the log file
    # Usage: WriteLog "<log>"
    function WriteLog {
       param ([string]$logString,[switch]$writehost)
        $logString = -join( [System.DateTime]::Now.ToString("yyyy-MM-dd hh:mm:ss"), "  ", $logString )
        Add-content $Logfile -value $logString -Force
        if($writehost){Write-Host -ForegroundColor Yellow $logString}
    }
 
    # DeleteService: Delete a service
    # Usage: DeleteService "Service name"
    function DeleteService {
        param([string]$serviceName)
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        if($service) {
            $service.StopService()
            $service.delete()
        }
        else {
            WriteLog("Service $serviceName does not exists!") -writehost
        }
    }
 
    # Run: Run a task and log the output
    # Usage: Run "command" "description of the command"
    function Run {
        param(
              [Parameter(Position = 0)]
              [string]$cmd,
              [Parameter(Position = 1)]
              [string]$description
            )
        Write-Host -ForegroundColor Green "COMMAND: {$description}"
        $cmdOutput = Invoke-Expression -Command "$cmd" | Out-String
        if($cmdOutput)
        {
            Write-Host -ForegroundColor Magenta ("$cmdOutput")
        }
        else
        {
            Write-Host -ForegroundColor Yellow ( "NO COMMAND OUTPUT")
        }
    }
 
    # StopProcess: Kill a task and log the output.
    # Usage: StopProcess "notepad"
    function StopProcess {
        param([string]$pName)
        if((Get-Process $pName -ErrorAction SilentlyContinue) -eq $null) {
            WriteLog("Process $pName is not running.")
        }
        else {
            Run "Get-Process $pName -ErrorAction SilentlyContinue| Stop-Process -force -ErrorAction SilentlyContinue" "Killing process $pName.exe"
        }
    }
 
    # RemoveItem: Delete a registry key / file and log the output
    # Usage: RemoveItem "HKLM:\Software\TrendMicro\Deep Security Agent"
    function RemoveItem {
        param([string]$item,[switch]$prompt=$False)
        if(Test-Path($item)) {
            Run "Remove-Item -Path '$item' -Force -Recurse -ErrorAction SilentlyContinue -confirm:$prompt" "Remove-Item -Path '$item' -Force -Recurse"
        }
        else {
             WriteLog ("$item does not exist.") -writehost
        }
    }
}#Begin
Process
{
    $ErrorActionPreference = 'SilentlyContinue'
    WriteLog("Script starts at $ScriptDir...") -writehost
 
    # Check CPU architecture
    $arch = (Get-WmiObject -Class Win32_ComputerSystem).SystemType.SubString(0,3)
    WriteLog("CPU arch $arch")
 
    # Reset the agent
    WriteLog("Attempting to Unregister Trend") -writehost
    Run "& `"$DsaInstallDir\dsa_control`" -r" "Reset agent" -ErrorAction SilentlyContinue
 
    #$productids = get-item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where{$($_ | Get-ItemProperty).displayname -match "Trend"}
     
    # Try normal uninstallation first. Assume failure if the agent cannot be uninstalled in 5 minutes
    WriteLog("[Step 1]. Try normal uninstallation first.") -writehost
 
    #Try Armor Agent Removal
    run "c:\.armor\opt\armor trend uninstall" "ArmorAgent Trend Uninstall:"
 
    #Check for remaining Registered Products
    $productids = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where{$_.displayname -match "^Trend Micro Deep Security Agent$"}).PSChildName,
    ((Get-ItemProperty HKLM:\SOFTWARE\Classes\Installer\Products\* | Where-Object {$_.ProductName -match "^Trend Micro Deep Security Agent"}).ProductIcon| Select-String -Pattern "{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}").matches.value | select -Unique
 
    #MSI Uninstall of remaining Products
    if($productids)
    {
        foreach($productid in $productids)
        {
            $args = @(
            "/X"
            $productid
            "/passive"
            "/norestart"
            "/l* $ScriptDir\Trend_MSIUninstall_log.txt"
            )
            WriteLog("Product installer GUID is $productid")
            Run "Start-Process `"msiexec.exe`" -ArgumentList $args -Wait -NoNewWindow -ErrorAction SilentlyContinue" "Normal uninstallation: $productid"
            Sleep -Seconds 10
        }
    }
    else
    {
        Writelog("Normal Installation not Found. Proceeding to remove all Components.") -writehost
    }
 
    <#
    if($wmiObj) {
        #$guid = $wmiObj.IdentifyingNumber
        $guid = $wmiObj.PSChildName
        if($guid) {
            $args = @(
            "/X"
            $guid
            "/passive"
            "/norestart"
            "/l* $ScriptDir\Trend_MSIUninstall_log.txt"
            )
            WriteLog("Product installer GUID is $guid")
            Run "Start-Process `"msiexec.exe`" -ArgumentList $args -Wait -NoNewWindow -ErrorAction SilentlyContinue" "Normal uninstallation" # "& MsiExec.exe /X `"$guid`" /qn /norestart " "Normal uninstallation"    
            Sleep -Seconds 10
        }
    } else {Writelog("Normal Installation not Found. Proceeding to remove all Components.") -writehost}
    #>
 
    # Stop services
    WriteLog("[Step 2]. Stop services") -writehost
 
    Run "Stop-Service ds4agent -ErrorAction SilentlyContinue"  "Stop-Service ds_agent"
    Run "Stop-Service ds_notifier -ErrorAction SilentlyContinue"  "Stop-Service ds_notifier"
    if("10.".Equals($prodVer)) {
        Run "Stop-Service ds_monitor"  "Stop-Service ds_monitor"
    }
    Run "Stop-Service amsp -ErrorAction SilentlyContinue" "Stop-Service amsp"
    Run "Stop-Service tbimdsa -nowait -ErrorAction SilentlyContinue" "Stop-Service tbimdsa"
    #Sleep -Seconds 10 #User network disconnected
 
    # Kill remaining processes
    WriteLog("[Step 3]. Kill remaining processes") -writehost
 
    StopProcess("ds_agent")
    StopProcess("dsa")
    StopProcess("notifier")
    StopProcess("coreframeworkhost")
    StopProcess("coreserviceshell")
    StopProcess("AMSP_LogServer")
    StopProcess("dsc")
  
    # Uninstall services
    WriteLog("[Step 4]. Uninstall services") -writehost
 
    Run "DeleteService('ds_agent')"  "DeleteService('ds_agent')"
    Run "DeleteService('amsp')"  "DeleteService('amsp')"
    Run "DeleteService('ds_notifier')"  "DeleteService('ds_notifier')"
    if("10.".Equals($prodVer)) {
        Run "DeleteService('ds_monitor')"  "DeleteService('ds_monitor')"
    }
 
    # Uninstall drivers
    WriteLog("[Step 5]. Uninstall drivers") -writehost
 
    $oemlines =  & pnputil -e
    $oemFile = ""
 
    foreach($line in $oemlines) {
        WriteLog("$line")
        if($line.StartsWith("Published name")) {
            $oemFile = $line.Split(":")[1].Trim()
            WriteLog("oemFile: $oemFile")
        }
        elseif($line.Contains("Trend Micro Inc.")) {
            WriteLog("TrendMicro driver found, uninstall it!")
            Run "& pnputil -f -d $oemFile"  "& pnputil -d $oemFile" 
        }  
    }
 
# Delete registry keys
WriteLog("[Step 6]. Delete registry keys") -writehost
 
 
$PackageID = (Get-ItemProperty HKLM:\SOFTWARE\Classes\Installer\Products\* | Where-Object {$_.ProductName -match "^Trend Micro Deep Security Agent"}| Get-Item).PSChildName
 
#$keys +=  (HKLM:\SOFTWARE\Classes\installer\Products\$PackageID -ErrorAction SilentlyContinue).pspath
#$keys += (Get-Item HKLM:\SOFTWARE\Classes\Installer\Products\$PackageID -ErrorAction SilentlyContinue).pspath
#$keys += (Get-Item HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes\$PackageID -ErrorAction SilentlyContinue).pspath
#$keys += (Get-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$PackageID -ErrorAction SilentlyContinue).pspath
 
 
<#
if($wmiObj) {
    $guid = $wmiObj.PSChildName.Replace("{","").Replace("}","")
  
    # Still try to uninstall first
 
    RemoveItem("HKLM:\SOFTWARE\Classes\Installer\Features\$guid")
    RemoveItem("HKLM:\SOFTWARE\Classes\Installer\Products\$guid")
    RemoveItem("HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes\$guid")
    RemoveItem("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\$guid")
    RemoveItem("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$guid}")
}
else {
    WriteLog("Cannot find DSA installer GUID, part of registry might not be deleted.")
}
#>
    if($productids)
    {
        WriteLog -logString $productids -writehost
        foreach($productid in $productids)
        {
            $guid = $productid.trim('{}','')
            if($guid -match "[a-f0-9]{8}(-|[a-f0-9]{4,24})"){
                RemoveItem("HKLM:\SOFTWARE\Classes\Installer\Features\$guid")
                RemoveItem("HKLM:\SOFTWARE\Classes\Installer\Products\$guid")
                RemoveItem("HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes\$guid")
                RemoveItem("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\$guid")
                RemoveItem("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$guid}")
            }
        }
    }
    if($PackageID)
    {
        foreach($package in $PackageID)
        {
            $keys = @(
                "HKLM:\SOFTWARE\Classes\installer\Products\$Package",
                "HKLM:\SOFTWARE\Classes\Installer\Products\$Package",
                "HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes\$Package",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$Package"
                )
 
            $keys | foreach{if($_ -match "\[a-f0-9]{24,32}"){ RemoveItem($_) -prompt}}
        }
    }
    if(!($PackageID -or $productids))
    {
        WriteLog("Cannot find DSA installer PackageID, part of registry might not be deleted.") -writehost
    }
 
 
"ds_agent","Amsp","ds_notifier","ds_monitor","tmactmon","tmcomm","tmevtmgr","tbimdsa" | foreach{
    RemoveItem("HKLM:\SYSTEM\CurrentControlSet\Services\$_")
}
 
    RemoveItem((Get-ItemProperty HKCR:\installer\Products\* | Where-Object{$_.ProductName -match "^Trend Micro Deep Security Agent$"} | Get-Item).pspath.tostring())
    RemoveItem("HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Deep Security Agent")
    RemoveItem("HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Deep Security Relay")
    RemoveItem("HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System\tbimdsa\")
 
    RemoveItem("HKLM:\Software\TrendMicro\Deep Security Agent")
    RemoveItem("HKLM:\Software\TrendMicro\AMSP")
    RemoveItem("HKLM:\Software\TrendMicro\AEGIS" )
    RemoveItem("HKLM:\Software\TrendMicro\AMSPStatus")
    RemoveItem("HKLM:\Software\TrendMicro\WL")
 
    # Remove directories and files
    WriteLog("[Step 7]. Remove directories and files") -writehost
 
    RemoveItem("$DsaInstallDir")
    RemoveItem("$env:programfiles\Trend Micro\AMSP")
    RemoveItem("C:\WINDOWS\System32\Drivers\tmebc.sys")
    RemoveItem("C:\WINDOWS\System32\Drivers\TMEBC64.sys")
    RemoveItem("C:\WINDOWS\System32\Drivers\tmactmon.sys")
    RemoveItem("C:\WINDOWS\System32\Drivers\tmcomm.sys")
    RemoveItem("C:\WINDOWS\System32\Drivers\tmevtmgr.sys")
    RemoveItem("C:\WINDOWS\System32\Drivers\tbimdsa.sys")
 
    WriteLog("[Step 8]. Create task to re-install Agent") -writehost
    $taskname = 'Armor Trend Install'
    $taskdescr = 'Task to re-install Trend after a necessary Reboot. Task should auto-delete, however, if it does not, then manually remove'
    $actionpath = 'C:\.armor\opt\armor.exe'
    $actionargs = 'trend install'
    try
    {
        $ErrorActionPreference = 'stop'
        $taskservice = New-Object -ComObject "schedule.service" -ErrorAction Stop
        $taskservice.connect()
        $taskfolder = try{$taskservice.GetFolder('\Armor Defense')}catch{$taskservice.GetFolder('\')}
        $taskdefinition = $taskservice.NewTask(0)
        $taskdefinition.RegistrationInfo.Description = $taskdescr
        $taskdefinition.RegistrationInfo.Author = -join ($env:USERDOMAIN,'\',$env:USERNAME)
        $taskdefinition.Settings.Enabled = $true
        $taskdefinition.Settings.AllowDemandStart = $true
        $taskdefinition.Settings.DeleteExpiredTaskAfter = 'PT0S'
        $TaskDefinition.Settings.ExecutionTimeLimit = "PT72H"
        $taskdefinition.Principal.Id = 'Author'
        $taskdefinition.Principal.UserId = 'NTAuthority\SYSTEM'
        $taskdefinition.Principal.LogonType = 5
        $taskdefinition.Principal.RunLevel = 1
        $trigger = $taskdefinition.Triggers.Create(8) | where{$_}
        $trigger.EndBoundary = $(get-date).AddDays($taskexpirationdays).ToString("yyyy-MM-ddTHH:mm:ss")
        $trigger.Enabled  = $true
        $trigger.Delay = 'PT5M'
        $action = $taskdefinition.Actions.Create(0)
        $action.Path = $actionpath
        $action.Arguments = $actionargs
        $taskfolder.RegisterTaskDefinition($taskname, $taskdefinition, 6, 'SYSTEM', $null, 5, '') | Out-Null
        $task =  $taskfolder.GetTask('Armor Trend Install') | select `
        Name, `
        Path, `
        @{name='TaskState';e={switch($_.state){0 {'Unknown'};1 {'Disabled'};2 {'Queued'};3 {'Enabled/Ready'};4 {'Running'}}}}, `
        @{name='TriggerType';e={switch($_.Definition.Triggers.getenumerator().type){6 {"On Idle"};;8 {"On Startup"}; 9 {"Logon"}}}}, `
        @{name='Action';e={-join ($_.Definition.Actions.getenumerator().path.tostring(),' ',$_.Definition.Actions.getenumerator().arguments)}}, `
        @{n='TaskExpiration';e={[datetime]$_.Definition.Triggers.getenumerator().EndBoundary}} | Out-String
 
        WriteLog($task) -writehost
    }
    Catch
    {
        WriteLog("Unable to create task - $taskname") -writehost
        WriteLog $_
    }
     
    # Ask the user to reboot
    Write-Warning "You should reboot the computer to complete force uninstallation of Deep Security Agent!"
    Write-Warning "If the computer is not restarted within 24 hours, you will need to manually re-install Malware protection`n`n"
    #Invoke-Expression "c:\.armor\opt\armor.exe show subagents"
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

    if($RebootAfterUninstall) {
        Restart-Computer -Force
    }
 
}# Process ScriptBlock