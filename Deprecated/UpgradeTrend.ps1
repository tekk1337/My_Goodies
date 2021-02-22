<#
.Synopsis
   Script used internally to upgrade/downgrade the Armor Trend DSA Subagent
   At the most simplistic level, you should just be able to run '.\upgradetrend.ps1' and have a successful upgrade.
   All parameters are meant to be used by more experienced senior engineers to troubleshoot more troublesome upgrades.

.DESCRIPTION
   This script specifically stops all trend components before attempting uninstallation. This alleviates the need for a reboot in most cases.
   This script IS NOT a miracle worker. If your trend installation was brokent before, it will continue to be broken.
   In rare circumstances, the Trend AMSP driver will still fail to stop. In these circumstances, the script should halt and make no further changes. Your installation will need to be repaired before the script can be run successfully.


.NOTES
   Feedback and questions should be directed to brandon Spell and Steve Silvidi in Slack.
.EXAMPLE
   PS C:\> .\TrendUpgrade_Final.ps1

   The most basic usage of the script. this will go through and uninstall/reinstall trend with the latest version and output full detail in jSON Format
.EXAMPLE
   PS C:\> .\TrendUpgrade_Final.ps1 -GetSubagents

   instead of performing any installation steps, this will just show subagents.
.EXAMPLE
   PS C:\> .\TrendUpgrade_Final.ps1 -RemoveOnly

   Uninstalls trend only. You should still be able to run '.\TrendUpgrade_Final.ps1' with no switches to re-install the newest version.

.EXAMPLE
   PS C:\> .\TrendUpgrade_Final.ps1 -TrendInstaller C:\Users\armoradmin\desktop\Agent-Core-Windows-11.3.0-376.x86_64.msi

   will install the specific version of trend
#>
[CmdletBinding(DefaultParameterSetName='none')]
Param(
    # Performs a 'read' operation of currently installed Armor Subagents. including the Trend Agent.
    [Parameter(ParameterSetName = 'ShowSubAgents')]
    [switch]$ShowSubAgents,

    # Performs an uninstallation of any existing Trend Agents. Useful if the standard upgrade is failing.
    [Parameter(ParameterSetName = 'RemoveOnly')]
    [switch]$RemoveOnly,


    #[Parameter(ParameterSetName = 'Install')]
    #[switch]$Install,

    #Installs the trend based on the specific installer that you specify.
    [Parameter(ParameterSetName = 'TrendInstaller')]
    [string]$TrendInstaller,

    # performs a re-registration of trend only. Registration will use standard Armor Naming convention.
    [Parameter(ParameterSetName = 'RegisterOnly')]
    [switch]$RegisterOnly,

    # performs uninstall/reinstall/register, despite any errors encountered.
    [switch]$Force
)
<#Check for Admin priveleges
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You are not running this as an Administrator!"
    #Start-Process -Verb "Runas" -File PowerShell.exe -Argument "-STA -noprofile -file $($myinvocation.mycommand.definition)"
    #Break
    exit 1
}
#>



#Set Variables
$starttime = [datetime]::Now

$Properties = @('Hostname',
'preUpgradeVersion',
'postUpgradeVersion',
'TrendRemovalSuccess',
'TrendInstallSuccess',
'TrendRegistrationSuccess',
'isSuccessfulUpgrade',
'Message');

$Output = New-Object psobject -Property @{
    Hostname = $env:COMPUTERNAME
    preUpgradeVersion = ''
    postUpgradeVersion = ''
    TrendRemovalSuccess = $true
    TrendInstallSuccess = $true
    TrendRegistrationSuccess = $true
    isSuccessfulUpgrade = $false
    Message = [string[]]@()
};
$UninstallRegKey = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue| Get-ItemProperty | Where-Object { $_.displayname -match 'Trend\sMicro\sDeep\sSecurity\sAgent' }
$TrendUpgradeLog = 'C:\.armor\log\TrendUpgrade.log'
Remove-Item $TrendUpgradeLog -erroraction silentlycontinue

#Define Functions
function showsubagents{
    $output = @()
    # show subagents powershell script
    $reg = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty

    "Trend","Panopta","Qualys" | ForEach-Object {
        $tmpout = '' | select Subagent,Version,Installed
        $tmpout.Subagent = $_
        $key = $reg | Where-Object { $_ -match $tmpout.Subagent }
        $tmpout.Installed = ( -not [string]::IsNullOrEmpty($key) )

        if ( $tmpout.Installed ) { 
            if ( $tmpout.Subagent -Match 'Trend' ){
                  
                    $trendinstall = Get-ItemProperty 'HKLM:\SOFTWARE\TrendMicro\Deep Security Agent' -ErrorAction SilentlyContinue
                    try {
                        $tmpout.Version = $trendinstall.InstalledVersion
                    } catch {}
                } else {
                $tmpout.Version = try { 
                    $key.displayversion 
                } catch { }
            }
        }

        $output+= $tmpout
    }
    'Filebeat','Winlogbeat' | ForEach-Object {
        $filepath = Get-Item -Path "c:\.armor\opt\$_*" -ErrorAction SilentlyContinue | Where-Object{$_.PSIsContainer} | select -First 1
        $tmpout = '' | select Subagent,Version,Installed
        $tmpout.Subagent = $_
        $tmpout.Installed = Test-Path $filepath.fullname
        if ( $tmpout.Installed ) {
            $tmpout.Version = ($filepath.Name | Select-String "\d\.\d\.\d").Matches[0].Value
        } else { '' }
        $output += $tmpout
    }

    $output
}
Function Write-Log($InputObject,[switch]$Break,[switch]$Passthru){
    
    if ( [string]::IsNullOrEmpty( $InputObject ) ) { return }
    if ( -not ( Test-Path $TrendUpgradeLog ) ) {
        $FileCreation = New-Item $TrendUpgradeLog -Force -ItemType File -ErrorAction SilentlyContinue
        Add-Content -Path $TrendUpgradeLog -Value "$(Get-Date -format s)`t`t File Created: $TrendUpgradeLog"
        ( $FileCreation | Out-String ).trim() -split "`n" | ForEach-Object {
            if ( (-not [string]::IsNullOrEmpty( $_ ) ) -and (-not [string]::IsNullOrWhiteSpace( $_ ) ) ) {
                $msg = "$( Get-Date -format s )`t $_"
                Add-Content -Path $TrendUpgradeLog -Value $msg -ErrorAction SilentlyContinue
            }
        } -ErrorAction SilentlyContinue
    }

    if ( $Break ) { 
        $separator = '__' * 50
        Add-Content -path $TrendUpgradeLog -value "$(Get-Date -format s)`t $separator" 
    }
    ( $InputObject | Out-String | Where-Object { $_ } ).trim() -split "`n" | ForEach-Object {
        if ( (-not [string]::IsNullOrEmpty( $_ ) ) -and (-not [string]::IsNullOrWhiteSpace( $_ ) ) ) {
            $msg = "$( Get-Date -format s )`t $_"
            Add-Content -Path $TrendUpgradeLog -Value $msg -ErrorAction SilentlyContinue
            if ( $Passthru ) { Write-Host -Object $msg }
        }
    }
}
Function ResetTrend{
    $dsa_control = "$Env:ProgramFiles\Trend Micro\Deep Security Agent\dsa_control.cmd"

    if ( Test-Path $dsa_control ) {

        $eapref = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        Write-Log 'Disabling Self Protection if enabled.' -Passthru
        $resetprotection = Invoke-Expression "& '$dsa_control' --selfprotect=0" -ErrorAction SilentlyContinue
        
        Write-Log "Resetting Trend DSA" -Passthru
        $resetDSA = Invoke-Expression "& '$dsa_control' -r" -ErrorAction Stop

        if ( ( $resetprotection -match "couldn't\sconnect\sto"  ) -or ( $resetDSA -match "couldn't\sconnect\sto"  ) ) {

            Write-Log "dsa_control could not connect to local service. Either Agent is not running, or installation is corrupted." -Passthru

        } else {

            Write-Log $resetprotection -Passthru

            Write-Log $resetDSA -Passthru

        }

        $ErrorActionPreference = $eapref

        Remove-Variable eapref -ea SilentlyContinue

    } else {

        Write-Log "ERROR: dsa_control.cmd not detected. " -Passthru

    }

}
Function StopTrend{
    
    $processes = 'ds_agent','dsa','notifier','coreframeworkhost','coreserviceshell','amsp_logserver','dsc'
    $drivers = 'tmactmon','tmevtmgr','tmcomm','tmumh','tmebc','tbimdsa'
    $services = 'AMSP','ds_agent','ds_monitor','ds_notifier'
    $Success = $true

    ResetTrend

    Write-Log 'Stopping Trend DSA Components.' -Passthru

    #Stop Services
    if ( $Success ) {

        foreach ( $service in $services ) {

            Write-Log "Stopping Service: $service" -Passthru

            $servicestatus = Get-Service -Name $service -ErrorAction SilentlyContinue

            if ( -not ( [string]::IsNullOrEmpty( $servicestatus ) ) ) {

                $Attempts = 0

                while ( $servicestatus.Status -ne 'Stopped' ) {

                    try {

                        $servicestatus | Stop-Service -ErrorAction Stop -WarningAction SilentlyContinue

                        Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue

                        $servicestatus = Get-Service -Name $service -ErrorAction SilentlyContinue

                    } catch {

                        Write-Log ( 'Error Stopping service "{0}": {1}' -f $service,$_.exception.message ) -Passthru

                    }

                    Start-Sleep -Seconds 5

                    $Attempts++

                    if ($Attempts -gt 5 ){break}

                }

            } else {

                Write-Log "$services service not found."

            }
        }

        $RunningServices = Get-Service -Name $services -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Stopped' }

        $Success = [string]::IsNullOrEmpty( $RunningServices )

    } else {

        return $false

    }

    #Stop Processes
    if ( $Success ) {

        foreach ( $process in $processes ) {

            Write-Log "Stopping proces: $process" -Passthru

            $procstatus = Get-Process $process -ErrorAction SilentlyContinue

            if ( -not ( [string]::IsNullOrEmpty( $procstatus ) ) ) {

                $Attempts = 0

                while ( -not ( [string]::IsNullOrEmpty( $procstatus ) ) ) {

                    try {

                        $procstatus | Stop-Process -ErrorAction Stop -Force -Confirm:$false

                        $procstatus = Get-Process $process -ErrorAction SilentlyContinue

                    } catch {

                        Write-Log ( 'Error Stopping process "{0}": {1}' -f $processes,$_.exception.message ) -Passthru
                    }

                    $Attempts++

                    if ( $Attempts -gt 5 ) {

                        break

                    }

                }

            } else {

                Write-Log "$process process not running." -Passthru

            }

        }
        $RunningProcesses = Get-Process -Name $processes -ErrorAction SilentlyContinue

        $Success = [string]::IsNullOrEmpty( $RunningProcesses )

    } else {

        #if stopping services, processes, or drivers fails, try to start everything back up and return false
        $services | ForEach-Object -Process { 

            Set-Service -Name $_ -StartupType Automatic -ErrorAction SilentlyContinue

            Start-Service -Name $_ -ErrorAction SilentlyContinue

        }

        $drivers | ForEach-Object -Process {

            Set-Service -Name $_ -StartupType Automatic -ErrorAction SilentlyContinue

            Start-Service -Name $_ -ErrorAction SilentlyContinue

        }

        return $false

    }

    #Stop Drivers
    if ( $Success ) {

        foreach ( $driver in $drivers ) {

            Write-Log "Stopping Driver: $driver" -Passthru

            $driverstatus = Get-Service -Name $driver -ErrorAction SilentlyContinue

            if ( -not ( [string]::IsNullOrEmpty( $driverstatus ) ) ) {

                $Attempts = 0

                while ( $driverstatus.Status -ne 'Stopped' ) {

                    try {

                        $driverstatus | Stop-Service -ErrorAction Stop -WarningAction SilentlyContinue

                        Set-Service $driver -StartupType Disabled -ErrorAction SilentlyContinue

                        $driverstatus = Get-Service -Name $driver -ErrorAction SilentlyContinue

                    } catch {

                        Write-Log ( 'Error Stopping driver "{0}": {1}' -f $driver,$_.exception.message ) -Passthru

                    }

                    Start-Sleep -Seconds 5

                    $Attempts++

                    if ($Attempts -gt 5 ){break}

                }

            } else {

                Write-Log "$services service not found." -Passthru

            }
        }

        $RunningDrivers = Get-Service -Name $drivers -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Stopped' }

        $Success = [string]::IsNullOrEmpty( $RunningDrivers )

    } else {

        #if stopping services, processes, or drivers fails, try to start everything back up and return false
        $services | ForEach-Object -Process { 

            Set-Service -Name $_ -StartupType Automatic -ErrorAction SilentlyContinue

            Start-Service -Name $_ -ErrorAction SilentlyContinue

        }
        $drivers | ForEach-Object -Process {

            Set-Service -Name $_ -StartupType Automatic -ErrorAction SilentlyContinue

            Start-Service -Name $_ -ErrorAction SilentlyContinue

        }

        Start-Service $drivers -ErrorAction SilentlyContinue #amsp services sometimes dont start the first time. Double-tapping it.

        return $false

    }

    return $Success
}
Function RevertTrend{
    $services = 'AMSP','ds_agent','ds_monitor','ds_notifier'

    foreach ( $service in $services ) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue

        if ( [string]::IsNullOrEmpty( $svc ) ) {
            Write-Log "Service does not exist: $service"
        } else {
            Write-Log "Starting Service: $service"
            while ( $svc.Status -ne 'Running' ) {
                try {
                    Set-Service $service -StartupType Automatic -ErrorAction Stop
                    $svc | Start-Service -ErrorAction Stop -WarningAction SilentlyContinue
                    $svc = Get-Service -Name $service
                } catch {
                    Write-Log ( 'Error Stopping Service "{0}": {1}' -f $service,$_.exception.message )
                    Write-Log "$count attempts remaining"
                }
                $count--
                if (-not $count ) {break}
            }
        }
    }
}
Function UninstallTrend {
    $return = $false
    $UninstallRegKey = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.displayname -match 'Trend\sMicro\sDeep\sSecurity\sAgent' }
    
    $UninstallRegKey | ForEach-Object {

        Write-Log 'Uninstalling Trend Product:' -Passthru
        Write-Log ( $_ | Select DisplayName,PSChildName,DisplayVersion,Version,EstimatedSize,InstallSource,PSPath )

        [string[]]$UninstallString = $_.uninstallstring -replace "msiexec.exe ",""

        if ( $UninstallString -match "/X\{[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}" ) {
            $tempMSIuninstallLog = [system.io.path]::GetTempFileName()
            $UninstallString += '/norestart'
            $UninstallString += '/quiet'
            $UninstallString += "/lei `"$tempMSIuninstallLog`""

            Write-Log 'Uninstall String:'
            Write-Log $UninstallString

            #uninstall trend
            $msiUninstall = Start-Process "MsiExec.exe" -arg $UninstallString -Wait -PassThru

            $uninstalllog = Get-Content $tempMSIuninstallLog

            Write-Log ( 'Uninstallation finished with exit code: {0}' -f $msiUninstall.ExitCode )

        } else {

            Write-Log "Uninstall Key is invalid. Key should be deleted, then re-run script." -Passthru

        }

        #Cleanup Log file
        Remove-Item $tempMSIuninstallLog -Force -ErrorAction SilentlyContinue

        Write-Log $uninstalllog

        if ( -not $msiUninstall.ExitCode ) { $return = $true }

    }

    return $return
}
Function InstallTrend($MSIFile) {
    Write-Log 'Beginning Trend DSA Install.' -Passthru
    Try {
        if ( $MSIFile ) {
            $installer = Get-Item $MSIFile
        } else {
            #download Trend
            Write-Log ('Downloading Agent') -Passthru
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            $WebClient = New-Object System.Net.WebClient
            $WebClient.DownloadFile("https://3a.epsec.armor.com:4119/software/agent/Windows/x86_64/",  "$env:temp\agent.msi")
            $installer = Get-Item $env:temp\agent.msi
            if ( $installer.Length -eq 0 ) {
                throw 'Download size is 0 Bytes. Download Failed.'
            }
        }

        Write-Log ( 'Trend Agent: {0} Size: {1}' -f $installer.FullName,$installer.Length ) -Passthru

        #build install string
        $tempMSIinstallLog = [system.io.path]::GetTempFileName()
        Write-Log "Creating temporaty Log file: $tempMSIinstallLog"
        
        
        [string[]]$installstring = "/i $($installer.FullName)"
        $installstring +=  '/quiet'
        $installstring += 'ADDLOCAL=ALL'
        $installstring += "/lei `"$tempMSIinstallLog`""

        Write-Log 'Installer Arguments:'
        Write-Log $installstring

        #install and validate
        $msiInstall = Start-Process -FilePath msiexec -ArgumentList $installstring -Wait -PassThru -ErrorAction Stop
        if ( $msiInstall.ExitCode ) {
            throw "Install Failed with exitcode: $($msiInstall.ExitCode)"
        }

        #cleanup
        $installlog = Get-Content $tempMSIinstallLog
        Remove-Item $tempMSIinstallLog

        Write-Log $installlog
        Write-Log 'Trend DSA Installation Complete.' -Passthru
        Return [bool]( -not $msiInstall.ExitCode )

    } Catch {
        Write-Log ( 'Error Installing Trend DSA: {0}' -f $_.exception.message )
        return $false
    }
}
Function RegisterTrend {
    Write-Log 'Registering Trend DSA' -Passthru
    $dsa_control = "$Env:ProgramFiles\Trend Micro\Deep Security Agent\dsa_control.cmd"
    
    if ( Test-Path $dsa_control ) {
        # get armor core id and account id and set the dsa hostname
        try {
            if ( Test-Path 'c:\.armor\etc\core.datatest' ) {
                        $coredata = Get-Content 'c:\.armor\etc\core.data' | ConvertFrom-Json
                        $DSAname = '{0}__{1}' -f $coredata.AccountId,$coredata.CoreInstanceId    
            } else {
                $aa = iex "c:\.armor\opt\armor.exe show db"
                $cid = ( $aa|Select-String "[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}" ).Matches[0].value
                $acnt = ( $aa | Select-String "\s\d{4}\s" ).Matches[0].Value.Trim()
                $DSAname = '{0}__{1}' -f $acnt,$cid
            }
            if ( $DSAname -match "^\d{4}__[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}$" ) {
                $dsa_cfg = '-a dsm://3a.epsec.armor.com:4120/ "hostname:{0}"' -f $DSAname
                Write-Log "DSA hostname: $DSAname" -Passthru
            } else {
                Write-Log 'Trend DSA Registration unsuccessful: Unable to get CoreInstanceID' -Passthru
                return $false
            }

        } catch {
            Write-Log 'Trend DSA Registration unsuccessful: Armor agent not found' -Passthru
            return $false
        }

        # reset DSA
        ResetTrend

        #Register DSA
        Write-Log ( 'TREND COMMAND: {0}' -f ("& '$dsa_control' $dsa_cfg") )
        $registration = Invoke-Expression "& '$dsa_control' $dsa_cfg"
        write-log $registration -passthru

    } else {
        Write-Log 'Trend DSA Registration unsuccessful: dsa_control.cmd not found!' -Passthru
        return $false
    }
}

if ( $ShowSubAgents ) {
    showsubagents
} elseif ( $RegisterOnly ) {
        return ( RegisterTrend )
} else {
    #Check for existing Trend installation
    if ( -not ( [string]::IsNullOrEmpty( $UninstallRegKey ) ) ) {
        if ( $PSBoundParameters['RemoveOnly'] ) {
            if ( StopTrend ) {
                Write-Log 'Trend Successfully Stopped.' -Passthru
                UninstallTrend | Out-Null
                return ( showsubagents )
            } Else {
                Write-Log 'Failed to stop all Services. No changes Made to installation. Please re-run.'
                Write-Log 'If you continue to receive this error, please manually troubleshoot the error.'
                return ( showsubagents )
            }
            
        } else {
            $Output.preUpgradeVersion = ( showsubagents )[0].version
            $stoptrend = StopTrend
            if ( $stoptrend ) {
                $Output.Message += 'Info: Trend Services stopped.'
                $Output.TrendRemovalSuccess = UninstallTrend
                $Output.Message += 'Info: Trend Uninstallation Completed.'
            } else {
                $Output.TrendRemovalSuccess = $false
                $Output.Messages += 'Warning: Failed to stop all services. No changes made to Trend Installation.'
                RevertTrend
            }
        }

    } else {
        Write-Log 'Existing Trend Installation Not Detected.' -Passthru
        if ( $PSBoundParameters['RemoveOnly'] ) {
            return ( showsubagents )
        }

        $Output.TrendRemovalSuccess = $true
        $Output.Message += 'Info: Existing Trend Installation Not Detected.'
    }


    if ( $TrendInstaller ) {
        if ( Test-Path $TrendInstaller ) {
            InstallTrend -MSIFile $TrendInstaller | Out-Null
            RegisterTrend 
            return ( showsubagents )
        } else { "Invalid Path" }
    }



    #Trend Installation
    if ( $Output.TrendRemovalSuccess -or $TrendInstaller -or $Force) {

        if ( $TrendInstaller ) {

            if ( Test-Path $TrendInstaller ) {

                InstallTrend -MSIFile $TrendInstaller | Out-Null

                RegisterTrend 

                return ( showsubagents )

            } else { "Invalid Path" }

        } else {

            if ( $Force ) {
                Write-Log 'Force flag detected.'
            }

            $Output.TrendInstallSuccess = InstallTrend

            $Output.postUpgradeVersion = ( showsubagents )[0].version
            <#try {
                ( Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction stop | 
                    Get-ItemProperty | 
                        Where-Object { $_.displayname -match 'Trend\sMicro\sDeep\sSecurity\sAgent' } ).DisplayVersion
            } catch {'failed to retrieve'}
            #>
            $Output.Message += 'Info: Trend Installation Completed'


        }

    } else {

        $Output.TrendInstallSuccess = $false

        $Output.Message += 'Warning: Trend Removal Failed. Not proceeding with re-installation. Please login to server and review Log.'

        RevertTrend

    }

    #Register Trend
    if ( $Output.TrendInstallSuccess -or $Force ) {
        $Output.TrendRegistrationSuccess = RegisterTrend
        $Output.Message += 'Info: Trend Registration Completed.'
    } else {
        $Output.TrendRegistrationSuccess = $false
        $Output.Message += 'Warning: Trend Registration Failed. Please review Log for further details.'
    }

    #finalize and Output
    if ($Output.TrendInstallSuccess -and $Output.TrendInstallSuccess -and $Output.TrendRegistrationSuccess ) {
        $Output.isSuccessfulUpgrade = $true
    }
    $endtime = ([datetime]::Now).Subtract($starttime).totalseconds
    Write-Log "Trend Micro DSA upgrade completed in $endtime Seconds"
    $Output.Message += "Info: Trend upgrade completed in $endtime Seconds"
    $output.message += "Info: Upgrade Log Located at: $TrendUpgradeLog"
    $Output | Select-Object $Properties | ConvertTo-Json -Depth 2 -ErrorAction SilentlyContinue
}
