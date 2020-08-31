Write-Host "DFW"
" "
Get-ArmorWSUSClient -UpdateGroup Unassigned -Location DFW | Select-Object -Property ComputerName
" "
Write-Host "PHX"
" "
Get-ArmorWSUSClient -UpdateGroup Unassigned -Location PHX | Select-Object -Property ComputerName
" "
Write-Host "LHR"
" "
Get-ArmorWSUSClient -UpdateGroup Unassigned -Location LHR | Select-Object -Property ComputerName
" "
Write-Host "AMS"
" "
Get-ArmorWSUSClient -UpdateGroup Unassigned -Location AMS | Select-Object -Property ComputerName
" "
Write-Host "SIN"
" "
Get-ArmorWSUSClient -UpdateGroup Unassigned -Location SIN | Select-Object -Property ComputerName