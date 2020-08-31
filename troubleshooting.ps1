cls;
$FormatEnumerationLimit = -1
Write-Host "Hostname:" -ForegroundColor Yellow 
$env:COMPUTERNAME
" "
Write-Host "OS:" -ForegroundColor Yellow 
(Get-CimInstance Win32_OperatingSystem) | Select-Object Caption, ServicePackMajorVersion | Out-Default
" "
Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet* | findstr IPAddress
" "
Get-WmiObject –class Win32_processor | ft DeviceID,NumberOfCores,NumberOfLogicalProcessors
" "
Write-Host "Memory=" -ForegroundColor Yellow 
(systeminfo | Select-String 'Total Physical Memory:').ToString().Split(':')[1].Trim()
" "
Write-Host "System Uptime" -ForegroundColor Yellow
Write-Host (get-date) - (gcim Win32_OperatingSystem).LastBootUpTime.
" "
Write-Host "Pending Reboots" -ForegroundColor Yellow
Try
{
    $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
    $CBSRebootPend = $null
    $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ErrorAction Stop
    $HKLM = [UInt32] "0x80000002"
    $WMI_Reg = [WMIClass] "\\$env:COMPUTERNAME\root\default:StdRegProv"
    If ([Int32]$WMI_OS.BuildNumber -ge 6001) {$RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\");$CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"}
    $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
    $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequiYellow"
    $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
    $RegValuePFRO = $RegSubKeySM.sValue
    $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
    $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')
    $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")           
    $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")
    If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {$CompPendRen = $true}
    If ($RegValuePFRO) {$PendFileRename = $true}
    $CCMClientSDK = $null
    $CCMSplat = @{
        NameSpace='ROOT\ccm\ClientSDK'
        Class='CCM_ClientUtilities'
        Name='DetermineIfRebootPending'
        ComputerName=$env:COMPUTERNAME
        ErrorAction='Stop'
    }
    ## Try CCMClientSDK
    Try {$CCMClientSDK = Invoke-WmiMethod @CCMSplat} Catch [System.UnauthorizedAccessException] {
        $CcmStatus = Get-Service -Name CcmExec -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue
        If ($CcmStatus.Status -ne 'Running') {
            Write-Warning "Error - CcmExec service is not running."
            $CCMClientSDK = $null
        }
    } Catch {
        $CCMClientSDK = $null
    }
    If ($CCMClientSDK) {
        If ($CCMClientSDK.ReturnValue -ne 0) {
            Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"         
        }
        If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
            $SCCM = $true
        }
    }
    Else {
        $SCCM = $null
    }
    ## Creating Custom PSObject and Select-Object Splat
    $SelectSplat = @{
        Property=(
            #'Computer',
            #'CBServicing',
            #'WindowsUpdate',
            #'CCMClientSDK',
            #'PendComputerRename',
            #'PendFileRename',
            #'PendFileRenVal',
            'RebootPending'
        )}
    $results = New-Object -TypeName PSObject -Property @{
        #Computer=$WMI_OS.CSName
        #CBServicing=$CBSRebootPend
        #WindowsUpdate=$WUAURebootReq
        #CCMClientSDK=$SCCM
        #PendComputerRename=$CompPendRen
        #PendFileRename=$PendFileRename
        #PendFileRenVal=$($temp=$RegValuePFRO;for($i=0;$i -lt $temp.count;$i++){if(($temp[$i] -ne "") -or ($i %2 -eq 0)){$temp[$i]}})
        RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
    } | Select-Object @SelectSplat
}catch{Write-Warning "$_"}
$results | Out-Default
" "
Write-Host "Installed Antivirus Software" -ForegroundColor Yellow
" "
$antivirus = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -match "trend|mcafee|eset|symantec|norton|bitdefender|sophos|kapersky|avast|avg|avg|clamav|virus|endpoint protection|smart security|internet security" } | Select-Object -Property DisplayName | Out-Default
If ($antivirus = $null)
{
Write-Host "No Antivirus Installed"
}
" "
" "
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
    
    write-host ""
    #write-host "Instance: $i"
    write-host "Product: $product"
    write-host "Edition: $edition"
    write-host "Version: $version"
    write-host ""
}
}Else{
Write-Host "SQL Software not installed"
}
" "
Write-Host "Armor Agent Version and Status" -ForegroundColor Yellow
" "
$ErrorActionPreference = "SilentlyContinue"
$armoragent = $null;
$armordb = $null;
$armoragent = C:\.armor\opt\armor.exe show subagents
$armordb = C:\.armor\opt\armor.exe show db
If ($armoragent -ne $null)
{
$armoragent
$armordb
}
Else
{
Write-Host "Armor Agent Not Installed";
}
" "
Write-Host "Update Check"
wuauclt.exe /resetauthorization /detectnow /updatenow
  Write-Host "Searching for updates, please wait..."
  $SearchResult = (New-Object -ComObject Microsoft.Update.Searcher).Search("IsInstalled=0").Updates | ? {$_.MsrcSeverity -ne $null}
  $updates = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($update in $SearchResult) { $updates.Add($update) >> $null}
#  Write-Host "Downloading $($SearchResult.count) important updates..."
#  $downloader = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateDownLoader()
#  $downloader.Updates = $updates
#  $downloader.Download()
#  Write-Host "Installing $($SearchResult.count) important updates..."
#  $installer = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateInstaller()
#  $installer.Updates = $updates
#  $Result = $installer.Install()
  " "
  Write-Host "Installed Patches" -ForegroundColor Yellow
  " "
  Get-HotFix | Sort-Object -Property InstalledOn | Sort-Object -Descending | Select-Object -Property Description,HotFixID,InstalledOn | Select-Object -Last 10 
  Start-Sleep -Seconds 5
  " "
  Write-Host "Installed Software"
" "
Start-Sleep -Seconds 3
" "
Write-Host "Windows Features" -ForegroundColor Yellow
Get-WindowsFeature | Where InstallState -eq Installed | ft -a
" "
Write-Host "System Error Logs" -ForegroundColor Yellow
Get-EventLog -LogName System -EntryType Error,Warning -Newest 10 | ft -Wrap
" "
Start-Sleep -Seconds 5
" "
Write-Host "Application Error Logs" -ForegroundColor Yellow
Get-EventLog -LogName Application -EntryType Warning,Error -Newest 10 | ft -Wrap
" "