#Define Static routes to add
$routes = @(
    '100.64.0.0/10',
    '10.1.244.0/22',
    '10.0.0.0/16',
    '146.88.106.200/32',
    '10.1.180.200/32'
    )

#Add Kibana IPs to list of routes
[System.Net.Dns]::Resolve('kibana.secure-prod.services').addresslist|select -ExpandProperty ipaddresstostring | foreach{
    $r = -join ($_,'/32')
    if ( $routes -notmatch $r ) { $routes += $r }
}



#Delete routes if they exist
Get-NetRoute -DestinationPrefix $routes -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false

#Get the default gateway for physical NICs
$defaultgateway = Get-NetAdapter -Physical | where{$_.status -eq 'Up'} | Get-NetIPConfiguration|where{$_.ipv4defaultgateway}


#If more than one defaultgatway exists, filters out the wifi adapter
if($defaultgateway.count -gt 1) {
    $dgw = $defaultgateway | where{($_|get-netadapter).PhysicalMediaType -notmatch '802\.11'}
} else {
    $dgw = $defaultgateway
}


#set new route params
$newroutesplat = @{
    DestinationPrefix = ''
    InterfaceIndex = $dgw.IPv4DefaultGateway.InterfaceIndex
    AddressFamily = 'IPv4'
    NextHop = $dgw.IPv4DefaultGateway.NextHop
    RouteMetric = 5
}

#Add New routes
$routes | foreach{
    #specify route in route params
    $newroutesplat.DestinationPrefix = $_

    #create route and filter output to the 'persistent' object
    New-NetRoute @newroutesplat | where{$_.store -match 'PersistentStore'}
}