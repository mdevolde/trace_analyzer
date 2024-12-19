param (
    [string]$pcapFolder,
    [string]$deviceListFile,
    [string]$outputFolder,
    [string]$analyzerExe,
    [string]$deviceFile
)

# Check that the mandatory parameters are set
if (-Not (Test-Path -Path $pcapFolder)) {
    Write-Error "The PCAP folder is not found : $pcapFolder"
    exit 1
}
if (-Not (Test-Path -Path $deviceFile)) {
    Write-Error "The device list file is not found : $deviceFile"
    exit 1
}
if (-Not (Test-Path -Path $analyzerExe)) {
    Write-Error "The Rust executable is not found : $analyzerExe"
    exit 1
}
if (-Not (Test-Path -Path $deviceListFile)) {
    Write-Error "The devices list in a text file is not found : $deviceListFile"
    exit 1
}

$devices = Get-Content -Path $deviceFile

# Create the output folder if it does not exist
If (-Not (Test-Path -Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder | Out-Null
}

# Analyse for each device
foreach ($device in $devices) {
    $device = $device -replace "`r", "" # Remove windows carriage return
    $sanitizedDeviceName = $device -replace '[\\/:*?"<>|]', '_' -replace '\s+', '_' # Make sure to have a valid file name
    $deviceOutput = Join-Path -Path $outputFolder -ChildPath "${sanitizedDeviceName}.png"

    Write-Host "Analyse for the device : $device"

    & $analyzerExe -d $deviceListFile -P $pcapFolder -o $deviceOutput -v 0 -s "$device"
}

Write-Host "Analysis done, check the output folder : $outputFolder"
