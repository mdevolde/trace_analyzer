use calamine::{open_workbook, Reader, Xlsx};
use chrono::{DateTime, Timelike};
use pcap::Capture;
use std::collections::{BTreeMap, HashMap};
use plotters::prelude::*;
use plotters::prelude::Palette99;
use pnet;
use clap::Parser;


/// Simple tool to analyze device activity in a PCAP file
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Excel file containing the list of devices and their MAC addresses
    #[arg(short, long)]
    device_file: String,

    /// PCAP file to analyze for device activity
    #[arg(short, long)]
    pcap_file: String,

    /// Output file for the generated graph
    #[arg(short, long)]
    output_file: String,
}

/// Load MAC addresses from an Excel file
fn load_mac_addresses(file: &str) -> HashMap<String, String> {
    let mut workbook: Xlsx<_> = open_workbook(file).expect("Impossible to read the Excel file");
    let mut mac_mapping = HashMap::new();
    let names = workbook.sheet_names().to_owned();

    if let Ok(range) = workbook.worksheet_range(&names[0]) {
        for row in range.rows().skip(1) {
            let device = row[1].to_string();
            let mac = row[2].to_string().to_lowercase();
            mac_mapping.insert(mac, device);
        }
    }
    println!("Loaded MAC addresses for {} devices", mac_mapping.len());
    mac_mapping
}

/// Analyze a PCAP file for device activity
fn analyze_pcap(pcap_file: &str, mac_mapping: &HashMap<String, String>) -> BTreeMap<String, Vec<u32>> {
    let mut activity: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    let mut cap = Capture::from_file(pcap_file).expect("Impossible to read the PCAP file");

    while let Ok(packet) = cap.next_packet() {
        let timestamp = packet.header.ts.tv_sec as i64;
        let time = DateTime::from_timestamp(timestamp, 0).expect("Invalid timestamp");

        let hour = time.hour();

        if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet.data) {
            let src_mac = ethernet.get_source().to_string();
            let dst_mac = ethernet.get_destination().to_string();

            if let Some(device) = mac_mapping.get(&src_mac) {
                activity.entry(device.clone()).or_default().push(hour);
            }
            if let Some(device) = mac_mapping.get(&dst_mac) {
                activity.entry(device.clone()).or_default().push(hour);
            }
        }
    }
    activity
}

/// Plot device activity on a 24-hour graph (device usage per hour)
fn plot_device_activity(activity: &BTreeMap<String, Vec<u32>>, output_file: &str) {
    let root = BitMapBackend::new(output_file, (1280, 720)).into_drawing_area();
    root.fill(&WHITE).unwrap();

    let mut chart = ChartBuilder::on(&root)
        .caption("Hours of use of IoT devices", ("sans-serif", 30))
        .margin(5)
        .x_label_area_size(50)
        .y_label_area_size(50)
        .build_cartesian_2d(0..24, 0..7000)
        .unwrap();

    chart.configure_mesh().draw().unwrap();

    for (i, (device, hours)) in activity.iter().enumerate() {
        let color = Palette99::pick(i).to_rgba();
        let mut hour_counts = vec![0; 24];
        for hour in hours {
            hour_counts[*hour as usize] += 1;
        }
        chart
            .draw_series(LineSeries::new(
                (0..24).map(|h| (h as i32, hour_counts[h] as i32)),
                &color,
            ))
            .unwrap()
            .label(device)
            .legend(move |(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], color.clone()));
    }

    chart.configure_series_labels().border_style(&BLACK).draw().unwrap();
    println!("Generated graph: {}", output_file);
}

fn main() {
    let args = Args::parse();
    let device_file = args.device_file;
    let pcap_file = args.pcap_file;
    let output_file = args.output_file;

    let mac_mapping = load_mac_addresses(&device_file);
    let activity = analyze_pcap(&pcap_file, &mac_mapping);
    plot_device_activity(&activity, &output_file);
}
