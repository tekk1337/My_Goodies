$fw = @{
  PolicyStore = 'PersistentStore'
  ;DisplayName = 'Appgate_Connect'
  ;Description = 'Allow outbound connection to Rackspace Resources.' `
  ;Enabled = 'True'
  ;Profile = 'Any'
  ;Direction = 'Outbound'
  ;Action = 'Allow'
  ;RemoteAddress = @('100.64.0.0/10','10.0.0.0/8')
}
New-NetFirewallRule @fw