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