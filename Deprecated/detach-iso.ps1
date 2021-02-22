$VMs = (Get-Content servers.txt)
 
foreach($vm in $VMs){
    Get-CDDrive $vm | Set-CDDrive -NoMedia -StartConnected:$false
-Connected:$false -Confirm:$false
}