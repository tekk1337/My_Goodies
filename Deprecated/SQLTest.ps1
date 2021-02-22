Write-Host "SQL Software" -ForegroundColor Yellow
" "
$ErrorActionPreference = "SilentlyContinue"
If ( $SQLCMD = SQLCMD -Q "SELECT @@VERSION AS 'SQL Server Version';" ) {
$SQLCMD
}
Else {
Write-Host "SQL Software not Installed"
}