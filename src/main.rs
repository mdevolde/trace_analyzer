mod args;
mod graph;
mod mac_loader;
mod pcap_analysis;
mod utils;

use args::Args;
use clap::Parser;
use graph::{plot_device_activity_generic, plot_device_activity_median};
use mac_loader::load_mac_addresses;
use pcap_analysis::{
    folder::{analyze_pcap_folder, analyze_pcap_folder_median},
    single::analyze_pcap,
};
use utils::*;

/// Main function to parse arguments and run the analysis
fn main() {
    let args = Args::parse();
    let device_file = args.device_file;
    let output_file = args.output_file;
    let selected_devices = args.selected_device;
    let verbose = args.verbose;

    if verbose >= 1 {
        println!("Starting analysis...");
    }

    let mac_mapping = load_mac_addresses(&device_file, &selected_devices, verbose);

    if let Some(pcap_file) = args.pcap_file {
        let activity = analyze_pcap(&pcap_file, &mac_mapping, verbose);
        plot_device_activity_generic(
            activity.iter().map(|(k, v)| (k.clone(), v.clone())),
            &output_file,
            "Device Activity",
        );
    } else if let Some(folder) = args.pcap_folder {
        if selected_devices.len() != 1 {
            eprintln!("Error: For folder analysis, please select exactly one device.");
            return;
        }
        if args.median {
            let hourly_data = analyze_pcap_folder_median(&folder, &mac_mapping, verbose);
            let hourly_medians = calculate_hourly_medians(&hourly_data);
            plot_device_activity_median(
                &hourly_medians,
                &output_file,
                "Median Daily Device Activity",
                &selected_devices[0],
            );
        } else {
            let daily_activity = analyze_pcap_folder(&folder, &mac_mapping, verbose);
            plot_device_activity_generic(
                daily_activity.iter().map(|(k, v)| (k.clone(), v.clone())),
                &output_file,
                "Daily Device Activity",
            );
        }
    }

    if verbose >= 1 {
        println!("Graph saved to {}", output_file);
    }
}
