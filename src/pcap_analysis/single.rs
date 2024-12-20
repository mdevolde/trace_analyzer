use crate::utils::*;
use pcap::Capture;
use std::collections::{BTreeMap, HashMap};

/// Analyze a single PCAP file for device activity
pub fn analyze_pcap(
    pcap_file: &str,
    mac_mapping: &HashMap<String, String>,
    verbose: i32,
) -> BTreeMap<String, Vec<u32>> {
    let mut activity: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    let mut capture = Capture::from_file(pcap_file).expect("Impossible to read the PCAP file");

    if verbose >= 1 {
        println!("Analyzing PCAP file: {}", pcap_file);
    }

    analyze_packets(
        &mut capture,
        mac_mapping,
        |device, hour| activity.entry(device).or_default().push(hour),
        verbose,
    );

    activity
}
