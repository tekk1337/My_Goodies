param (
    [ValidatePattern("^([2346789BCDFGHJKMPQRTVWXY{5}]-?){5}")]
    [string]
    $license,
    [switch]
    $full = $false,
    [string]
    $region,
    [string]
    $downloadBase = "https://agent.armor.com"
)
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host("The Armor Agent installation must be run with Administrative privileges.");
    exit;
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

$installationDirectory = "C:\.armor\opt";
$logDirectory = "C:\.armor\log";
$tempLog = "$env:TEMP\armor-install.log";
$global:reg = $false;

function LogTemp ([string] $message) {
    $message | Tee-Object -append -file $tempLog;
}

function Download_Fallback ([string]$source, [string]$destination, [string]$userAgent) {
    $webClient = (New-Object System.Net.WebClient);
    $webClient.Headers.Add("User-Agent", $userAgent);
    $webClient.DownloadFile( $source, $destination);
}

function Download ([string]$source, [string]$destination) {
    try {
    Write-Host "Downloading $source to $destination";
    $userAgent = "Armor Powershell Bootstrap/1.0";

    if (Test-Path -PathType Leaf -Path $destination) {
        Remove-Item -Path $destination -Force;
    }

    if (Get-Command Invoke-WebRequest -errorAction SilentlyContinue) {
        Invoke-WebRequest $source -OutFile $destination -UserAgent $userAgent;
    }
    else {
        Download_Fallback $source $destination $userAgent;
    }
    } catch {
        Write-Host "Unable to download ${source}"
        Write-Host $_
        exit(1)
    }
}

function DownloadAgent
(
    [string] $agentSourceUrl,
    [string] $agentDestFilePath,
    [string] $sha1SourceUrl,
    [string] $sha1DestFilePath
) {
    Download $agentSourceUrl  $agentDestFilePath;
    Download  $sha1SourceUrl  $sha1DestFilePath;
}

Function Get-ShaHash([String] $filePath) {
    $fileStream = [System.IO.File]::OpenRead($filePath);
    $bytes = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash($fileStream);
    $fileStream.Dispose();

    return (($bytes | ForEach-Object { $_.ToString("X2") }) -join "");
}

function ValidateChecksum
(
    [string] $agentFilePath,
    [string] $sha1FilePath
) {
    $fileHash = Get-ShaHash $agentFilePath;
    $expectedHash = (Get-Content -Raw $sha1FilePath);
    if ($expectedHash) {
        $expectedHash = $expectedHash.Trim("`n").Trim().ToUpper();
    }

    if ($fileHash -ne $expectedHash) {
        LogTemp "Checksum does not match.  Exiting. ";
        ConcatLog $tempLog;
        exit;
    }
}

function ExtractAgent
(
    [string] $filePath,
    [string] $destFolderPath

) {
    try {
        [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null;
        [System.IO.Compression.ZipFile]::ExtractToDirectory($filePath, $destFolderPath);
    } catch {
        Write-Host "Unable to extract Armor Agent"
        Write-Host $_
        Exit(1)
    }
}

function SetupArmorPath ([string]$newPath) {
    New-Item -ItemType Directory -Path $newPath -Force -ErrorAction Inquire | Out-Null;
}

function ExecuteProcess(
    [string]
    $prefix,
    [string]
    $filePath,
    [string]
    $arguments
) {

    try {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo;
    $pinfo.FileName = $filePath;
    $pinfo.RedirectStandardError = $false;
    $pinfo.RedirectStandardOutput = $false;
    $pinfo.UseShellExecute = $false;
    $pinfo.Arguments = $arguments;
    $p = New-Object System.Diagnostics.Process;
    $p.StartInfo = $pinfo;

    $stdOutName = "${prefix}Out";
    $stdErrName = "${prefix}Error";

    $action = { Write-Host $Event.SourceEventArgs.Data }
    Register-ObjectEvent -InputObject $p `
        -EventName "OutputDataReceived" `
        -Action $action `
        -SourceIdentifier $stdOutName | Out-Null;
    Register-ObjectEvent -InputObject $p `
        -EventName "ErrorDataReceived" `
        -Action $action `
        -SourceIdentifier $stdErrName | Out-Null;

    $p.Start() | Out-Null;

    $p.WaitForExit();

    Unregister-Event -SourceIdentifier $stdOutName;
    Unregister-Event -SourceIdentifier $stdErrName;

    return $p.ExitCode;
    } catch {
        Write-Host "Exception attempting to execute ${prefix}"
        Write-Host $_
        return 1;
    }
}

function AgentServiceInstall ([string]$armorAgentPath) {
    Write-Host "Registering agent";
    try {
    $licenseUpper = $license.ToUpper();
    $arguments = "register --license `"$licenseUpper`" --region $region";
    ExecuteProcess "AgentServiceInstall" $armorAgentPath $arguments;
    if (Test-Path c:\.armor\etc\core.data -PathType Leaf) {
      $global:reg = $true;
    }
    } catch {
        Write-Host "Failed to register the armor agent"
        Write-Host "Please remove the c:\.armor\ directory and retry"
        Remove-Item -Path $PSCommandPath
        Write-Host $_
        exit(0)
    }
}

function ScheduleSupervisor ([string]$armorAgentPath) {
    Write-Host "Scheduling agent supervisor";
    # added 3 mins delay so that supervisor cron job for get-tasks,
    # and agent get-tasks cron job will not be created at same time.
    $start = "00:{0}" -f [datetime]::Now.AddMinutes((3 + 15)).Minute.ToString("00");
    $interval = 15;
    $schedule = "MINUTE";
    $user = "NT AUTHORITY\SYSTEM";
    $taskName = "\Armor Defense\SUPERVISOR_TASKS";
    $taskRun = "$armorAgentPath get-tasks";
    $arguments = "/create /f /sc `"${schedule}`" /tn `"${taskName}`" /tr `"${taskRun}`" /np /st `"${start}`" /mo `"$interval`" /k /ru `"${user}`"";

    ExecuteProcess "ScheduleSupervisor" "schtasks.exe" $arguments | Out-Null
}

function InstallAgent() {
    $agentSourceUrl = "$downloadBase/latest/armor-windows.zip";
    $agentTempFilePath = Join-Path $env:TEMP "armor-windows.zip";
    $sha1SourceUrl = "$downloadBase/latest/armor-windows.zip.sha1";
    $sha1TempFilePath = Join-Path $env:TEMP "armor-windows.zip.sha1";
    SetupArmorPath $installationDirectory;
    DownloadAgent $agentSourceUrl $agentTempFilePath $sha1SourceUrl $sha1TempFilePath;
    ValidateChecksum $agentTempFilePath $sha1TempFilePath;
    ExtractAgent $agentTempFilePath $installationDirectory;
    AgentServiceInstall (Join-Path $installationDirectory "armor.exe");
    if ($global:reg) {
        ScheduleSupervisor (Join-Path $installationDirectory "armor-supervisor.exe")
        InstallSubAgents
    }
}

function InstallSubAgents() {


    if ($full -and ($global:reg -eq $true))
    {

        TrendInstall(Join-Path $installationDirectory "armor.exe");
        FIMInstall(Join-Path $installationDirectory "armor.exe");
        IDSInstall(Join-Path $installationDirectory "armor.exe");
        AVInstall(Join-Path $installationDirectory "armor.exe");
        $dsaControl = Join-Path $Env:ProgramFiles "Trend Micro\Deep Security Agent\dsa_control";
        & $dsaControl -m;
        sleep 20;
        VulnInstall(Join-Path $installationDirectory "armor.exe");
        LoggingInstall(Join-Path $installationDirectory "armor.exe");
        TrendRecommendationScanInstall(Join-Path $installationDirectory "armor.exe");
        TrendRecommendationScanOngoingInstall(Join-Path $installationDirectory "armor.exe");
    }
}

function ConcatLog($FileName) {
    if (-not (Test-Path -PathType Container $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory | Out-Null;
    }
    $date = Get-Date -UFormat '+%Y-%m-%dT%H:%M:%SZ';
    $out = (Get-Content $FileName) -Join " ";
    $logEntry = "time=`"$date`" level=info msg=`"$out`"";
    Add-Content -Path (Join-Path $logDirectory "armor.log") -Value ($logEntry);
}

function TrendInstall ([string]$armorAgentPath) {
    Write-Host "Installing trend";
    $arguments = "trend install";
    ExecuteProcess "TrendInstall" $armorAgentPath $arguments | Out-Null
}

function TrendRecommendationScanInstall ([string]$armorAgentPath) {
    Write-Host "Installing trend";
    $arguments = "trend recommendation-scan";
    ExecuteProcess "TrendInstall" $armorAgentPath $arguments | Out-Null
}

function TrendRecommendationScanOngoingInstall ([string]$armorAgentPath) {
    Write-Host "Installing trend";
    $arguments = "trend ongoing-recommendation-scan on";
    ExecuteProcess "TrendInstall" $armorAgentPath $arguments | Out-Null
}

function AVInstall ([string]$armorAgentPath) {
    Write-Host "Installing av";
    $arguments = "av on";
    ExecuteProcess "AVInstall" $armorAgentPath $arguments | Out-Null
}

function FIMInstall ([string]$armorAgentPath) {
    Write-Host "Installing fim";
    $arguments = "fim on auto-apply-recommendations=on";
    ExecuteProcess "FIMInstall" $armorAgentPath $arguments | Out-Null
}

function IDSInstall ([string]$armorAgentPath) {
    Write-Host "Installing ids";
    $arguments = "ips detect auto-apply-recommendations=on";
    ExecuteProcess "IDSInstall" $armorAgentPath $arguments | Out-Null
}

function VulnInstall ([string]$armorAgentPath) {
    Write-Host "Installing vuln";
    $arguments = "vuln install";
    ExecuteProcess "VulnInstall" $armorAgentPath $arguments | Out-Null
}

function LoggingInstall ([string]$armorAgentPath) {
    Write-Host "Installing logging";
    $arguments = "logging install";
    ExecuteProcess "LoggingInstall" $armorAgentPath $arguments | Out-Null
}



## Main
New-Item $tempLog -Force -ErrorAction Ignore -ItemType file | Out-Null;

if (!$license) {
  Write-Host "License not provided. Will not install Armor agent"
  exit(1)
}

if (!$region) {
  Write-Host "Region not provided. Will not install Armor agent"
  exit(1)
}
ConcatLog $tempLog;
InstallAgent

Remove-Item -Path $PSCommandPath
