use clap::Parser;

/// Simple tool to analyze device activity in a PCAP file or folder
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Excel file containing the list of devices and their MAC addresses
    #[arg(short, long)]
    pub device_file: String,

    /// PCAP file to analyze for device activity (mutually exclusive with `pcap_folder`)
    #[arg(short, long, conflicts_with = "pcap_folder")]
    pub pcap_file: Option<String>,

    /// Folder containing multiple PCAP files to analyze for a single device's activity (mutually exclusive with `pcap_file`)
    #[arg(short = 'P', long, conflicts_with = "pcap_file")]
    pub pcap_folder: Option<String>,

    /// Output file for the generated graph
    #[arg(short, long)]
    pub output_file: String,

    /// To generate a graph with the median values instead of a comparative graph
    #[arg(long, conflicts_with = "pcap_file")]
    pub median: bool,

    /// Set the verbosity level. There are 3 levels of verbosity (0, 1, 2)
    #[arg(short, long, default_value = "1")]
    pub verbose: i32,

    /// Select one or more devices to analyze (optional, can be repeated)
    #[arg(short, long, num_args = 0.., action = clap::ArgAction::Append)]
    pub selected_device: Vec<String>,
}
