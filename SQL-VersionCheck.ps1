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
    
    Write-Host ""
    #Write-Host "Instance: $i"
    Write-Host "Product: $product"
    Write-Host "Edition: $edition"
    Write-Host "Version: $version"
    Write-Host ""
}
}Else{
Write-Host "SQL Software not installed"
}