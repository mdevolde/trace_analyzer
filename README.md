# Pcap reader

## Prelude
This tool was originally designed for the [Embedded System Security course (ELEC-H550)](https://www.ulb.be/en/programme/2023-elec-h550), given at the Université Libre de Bruxelles.

It was designed by a group comprising Martin Devolder, Virgile Devolder and Corentin Bouffioux.

## Requirements (Windows)
If you are using Windows, following this [explaination](https://github.com/libpnet/libpnet?tab=readme-ov-file#windows), we need to install npcap to use pnet.

You can download it from [here](https://npcap.com/#download).

Choose the "Npcap SDK" version and install it (zip file). Then, copy `Packet.lib` and `wpcap.lib` in the zip to the root of the project.

Then, return [here](https://npcap.com/#download) and download the "Npcap installer" (during the installation, choose the "Install Npcap in WinPcap API-compatible Mode" option).

## Requirements (general)
You need to have rust installed on your machine. You can install it by following the instructions on the [official website](https://www.rust-lang.org/tools/install).

## Excel file
Before you start, you'll need an excel file with the names of your devices (unique names) in the second column, and the MAC address (also unique) in the third.

It doesn't matter what's in the first column, just as it doesn't matter what's after the third.

The first line is ignored, so as to be able to have column headings.

Here's an example:

| Category           | Device Name            | MAC Address         | Companion App  |
|--------------------|------------------------|---------------------|----------------|
| Audio              | Amazon Alexa Echo Dot 1| 1A:FE:2B:98:16:DD   | Amazon Alexa   |
| Audio              | Amazon Alexa Echo Dot 2| A2:D0:DC:C4:08:FF   | Amazon Alexa   |
| Audio              | Amazon Alexa Echo Spot | DC:12:B0:9B:0C:EC   | Amazon Alexa   |
| Camera             | AMCREST WiFi Camera    | 09:7C:39:CE:6E:2A   | AmcrestViewPro |
| Camera             | Arlo Base Station      | CD:F4:11:9C:D0:00   | Arlo           |
| Home Automation    | Atomi Coffee Maker     | 44:A6:B8:F9:1B:88   | Atomi Smart    |

## Usage

To have help on the command line arguments, run the following command:
```powershell
cargo run -- --help
```

Here are a few examples:

### Analyze a pcap file
To analyze the activity in a PCAP file, you can issue this command (replace the paths with the ones on your machine):
```powershell
cargo run --release -- -d .\devices.xlsx -p .\2021_11_02.pcap -o result.png
```
This command will produce a graph showing the number of requests per hour for each device in the PCAP file.

### Analyse a pcap file for some devices
To analyze the activity in a PCAP file, but only for a few devices, you can issue this command (replace the paths with the ones on your machine):
```powershell
cargo run --release -- -d .\devices.xlsx -p .\2021_11_02.pcap -o result.png -s "Amazon Alexa Echo Dot 1" -s "Arlo Base Station"
```

### Analyze a pcap folder
To analyze the activity in a folder containing PCAP files, you can issue this command (replace the paths with the ones on your machine):
```powershell
cargo run --release -- -d .\devices.xlsx -P "E:\test" -o result.png -s "Atomi Coffee Maker"
```
This command will give, for the given device, a comparison, for all PCAP files in the folder, of requests per hour, on the same graph.

## Given ps1 scripts
There are also two given scripts (for Windows), which automate the execution of graph generation, for a multitude of appliances.

### Analyze all device activity for each pcap file
To automate execution of the command given in [Section : Analyse a pcap file for some devices](#analyse-a-pcap-file-for-some-devices) and the command given in [Analyze a pcap file](#analyze-a-pcap-file), you can run the script `analyze_all_device_each_day.ps1` (replace the paths with those of your machine):
```powershell
.\analyze_all_device_each_day.ps1 -pcapFolder "E:\PCAP" -deviceListFile "devices.xlsx" -outputFolder "output" -analyzerExe ".\target\release\trace_analyzer.exe" -deviceFile "devices.txt"
```
This command will, for all the PCAP files in the given folder, make an individual graph of all the devices given in the text file, then make the graph with all the devices in the PCAP.

### Analyze each device activity for all pcap files
To automate execution of the command given in [Section : Analyze a pcap folder](#analyze-a-pcap-folder), you can run the script `analyze_each_device_all_day.ps1` (replace the paths with those of your machine):
```powershell
.\analyze_each_device_all_day.ps1 -pcapFolder "E:\test" -deviceListFile "devices.xlsx" -outputFolder "output" -analyzerExe ".\target\release\trace_analyzer.exe" -deviceFile "devices.txt"
```
This command will, for all the devices given in the text file, generate the activity comparison graph for this device between all the PCAP files given in the folder.

#### Note
- The `devices.txt` file should contain the names of the devices you want to analyze, one per line.
- Theses commands suppose that `trace_analyzer` was compiled in the `release` mode, with the `cargo build --release` command.