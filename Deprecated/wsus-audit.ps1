$params = @('ComputerName','VMWare VMName','ServerIP','LastSyncTime','Exists','vCenter')
$wsusvms = Get-ArmorWSUSClient -ReportingStatus failed,notreporting -Location PHX,DFW,LHR,SIN,AMS

foreach( $wsusvm in $wsusvms ) {
    try {
        $vmwarevm = Get-ArmorVM -VMHostname "^$($wsusvm.ComputerName)$" -DataCenter $wsusvm.vcenter -ErrorAction Stop
        $vmstatus = ( -not [string]::IsNullOrEmpty( $vmwarevm ) )
        if ( $vmstatus ) {
            $vmwarevmname = $vmwarevm.name.split(' ')[0]
            $ip = $vmwarevm.ipaddress
        } else {
            $vmwarevmname = 'Not Found'
            $ip = 'Not Found'
        }
        $wsusvm | Add-Member -NotePropertyName 'VMWare VMName' -NotePropertyValue $vmwarevmname -Force
        $wsusvm | Add-Member -NotePropertyName 'ServerIP' -NotePropertyValue $ip -Force
        $wsusvm | Add-Member -NotePropertyName 'Exists' -NotePropertyValue $vmstatus -Force

    } catch {
        Write-Warning "Unable to retrieve results for $( $wsusvms.computername )"
        Write-Verbose $( $_.exception | Out-String )
    }
}
$wsusvms | sort vcenter,exists,lastsynctime,computername | ft -a -wr $params

$wsusvms | sort vcenter,exists,lastsynctime,computername | select $params | Export-Csv $env:USERPROFILE\desktop\wsusaudit.csv -NoTypeInformation