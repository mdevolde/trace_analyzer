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

# Loop on each pcap file
Get-ChildItem -Path $pcapFolder -Filter "*.pcap" | ForEach-Object {
    $pcapFile = $_.FullName
    $baseName = $_.BaseName

    Write-Host "Analyse on file : $pcapFile"

    # Analyse for each device
    foreach ($device in $devices) {
        $device = $device -replace "`r", "" # Remove windows carriage return
        $sanitizedDeviceName = $device -replace '[\\/:*?"<>|]', '_' # Make sure to have a valid file name
        $deviceOutput = Join-Path -Path $outputFolder -ChildPath "${baseName}_$($sanitizedDeviceName -replace '\s+', '_').png"
        Write-Host "  -> Generating graph for device : $device"
        & $analyzerExe -d $deviceListFile -p $pcapFile -o $deviceOutput -v 0 -s "$device"
    }

    # Analyse for all devices
    $globalOutput = Join-Path -Path $outputFolder -ChildPath "${baseName}_global.png"
    Write-Host "  -> Generating global graph"
    & $analyzerExe -d $deviceListFile -p $pcapFile -o $globalOutput -v 0
}

Write-Host "Analysis done, check the output folder : $outputFolder"
