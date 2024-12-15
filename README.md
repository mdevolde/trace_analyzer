# Pcap reader

## Requirements
Following this [explaination](https://github.com/libpnet/libpnet?tab=readme-ov-file#windows), we need to install npcap to use pnet.
You can download it from [here](https://npcap.com/#download).
Choose the "Npcap SDK" version and install it (zip file). Then, copy `Packet.lib` and `wpcap.lib` in the zip to the root of the project.
Then, return [here](https://npcap.com/#download) and download the "Npcap installer" (during the installation, choose the "Install Npcap in WinPcap API-compatible Mode" option).

## Usage

To have help on the command line arguments, run the following command:
```powershell
cargo run -- --help
```
