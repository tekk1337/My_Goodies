$UpdateSession = New-Object -ComObject Microsoft.Update.Session;

$UpdateSearcher = $UpdateSession.CreateUpdateSearcher();

$SearchResult = $UpdateSearcher.Search("IsInstalled=0 OR IsInstalled=1").Updates;

$HotFixData = Get-HotFix | select HotFixID,InstalledOn;

$HotFixArray =  @{};

$Data = @();

foreach ($hotfix in $HotFixData) {

    $HotFixArray[$hotfix.HotFixID] = $hotfix.InstalledOn

}


 foreach ($Update in $searchResult) {


    foreach ($Kb in $Update.KBArticleIDs) {


    $AvailableDate = $Update.LastDeploymentChangeTime.ToShortDateString();
    $Title = $Update.Title;
    $IsInstalled =  $Update.IsInstalled;
    $Name = "KB" +$Kb;
    $InstalledOn = "Unknown";

    if ($HotFixArray[$Name]) {
        $InstalledOn = $HotFixArray[$Name];
     }    


    if ($Update.count -gt 0) {
    
        $SecurityBulletinIds = $Update.SecurityBulletinIDs[0];
    
    }


    $Type = "update";



    if ($Title -like "*Security Update*") { $Type = "security" }
        $Data += ([PSCustomObject]@{KB=$Name; Type=$Type;IsInstalled=$IsInstalled;AvailableDate=$AvailableDate})
    }
 }


 ## Table output
 Write-Output ("Results For: {0}" -f ([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname)
 $Data | Format-Table -AutoSize | Out-String
 
 ## Json Output
 #$Data | ConvertTo-Json
 
 ## Csv Output
 #$Data | ConvertTo-Csv -NoTypeInformation