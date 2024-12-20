use crate::utils::*;
use pcap::Capture;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
};

/// Analyze multiple PCAP files for a single device's activity, distinguishing days
pub fn analyze_pcap_folder(
    folder: &str,
    mac_mapping: &HashMap<String, String>,
    verbose: i32,
) -> BTreeMap<String, Vec<u32>> {
    let mut daily_activity: BTreeMap<String, Vec<u32>> = BTreeMap::new();

    if verbose >= 1 {
        println!("Analyzing PCAP files in folder: {}", folder);
    }

    for entry in fs::read_dir(folder).expect("Failed to read directory") {
        let path = entry.expect("Failed to read entry").path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("pcap") {
            let file_name = path.file_stem().unwrap().to_string_lossy().to_string();
            let mut capture =
                Capture::from_file(path.to_str().unwrap()).expect("Failed to open PCAP");
            let mut hours = vec![];

            analyze_packets(
                &mut capture,
                mac_mapping,
                |_, hour| hours.push(hour),
                verbose,
            );

            if !hours.is_empty() {
                daily_activity.insert(file_name, hours);
            }
        }
    }

    if verbose >= 1 {
        println!("Finished analyzing folder.");
    }
    daily_activity
}

/// Analyze multiple PCAP files for a single device's activity, distinguishing days (but producing median values)
pub fn analyze_pcap_folder_median(
    folder: &str,
    mac_mapping: &HashMap<String, String>,
    verbose: i32,
) -> HashMap<u32, Vec<u32>> {
    let mut hourly_data: HashMap<u32, Vec<u32>> = HashMap::new();

    if verbose >= 1 {
        println!("Analyzing PCAP files in folder for median: {}", folder);
    }

    for entry in fs::read_dir(folder).expect("Failed to read directory") {
        let path = entry.expect("Failed to read entry").path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("pcap") {
            let mut capture =
                Capture::from_file(path.to_str().unwrap()).expect("Failed to open PCAP");

            let mut hourly_counts = vec![0; 24];

            analyze_packets(
                &mut capture,
                mac_mapping,
                |_, hour| hourly_counts[hour as usize] += 1,
                verbose,
            );

            for (hour, &count) in hourly_counts.iter().enumerate() {
                hourly_data.entry(hour as u32).or_default().push(count);
            }
        }
    }

    if verbose >= 1 {
        println!("Finished analyzing folder for median.");
    }

    hourly_data
}
