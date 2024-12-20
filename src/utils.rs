use chrono::{DateTime, Timelike};
use pcap::Capture;
use pnet;
use std::collections::HashMap;

/// Analyze packets from a PCAP capture
pub fn analyze_packets<F>(
    capture: &mut Capture<pcap::Offline>,
    mac_mapping: &HashMap<String, String>,
    mut process_activity: F,
    verbose: i32,
) where
    F: FnMut(String, u32),
{
    while let Ok(packet) = capture.next_packet() {
        let timestamp = packet.header.ts.tv_sec as i64;
        let time = DateTime::from_timestamp(timestamp, 0).expect("Invalid timestamp");
        let hour = time.hour();

        if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet.data) {
            let src_mac = ethernet.get_source().to_string();
            let dst_mac = ethernet.get_destination().to_string();

            if let Some(device) = mac_mapping.get(&src_mac) {
                process_activity(device.clone(), hour);
                if verbose > 1 {
                    println!("Device '{}' sent data at hour {}", device, hour);
                }
            }
            if let Some(device) = mac_mapping.get(&dst_mac) {
                process_activity(device.clone(), hour);
                if verbose > 1 {
                    println!("Device '{}' received data at hour {}", device, hour);
                }
            }
        }
    }
}

/// Count hourly activity
pub fn count_hourly_activity(hours: &[u32]) -> Vec<u32> {
    let mut hour_counts = vec![0; 24];
    for &hour in hours {
        hour_counts[hour as usize] += 1;
    }
    hour_counts
}

// Calculate the median of hourly counts
pub fn calculate_hourly_medians(hourly_data: &HashMap<u32, Vec<u32>>) -> Vec<u32> {
    let mut medians = vec![0; 24];

    for (&hour, counts) in hourly_data {
        let mut sorted = counts.clone();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        medians[hour as usize] = if sorted.len() % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) / 2
        } else {
            sorted[mid]
        };
    }

    medians
}
