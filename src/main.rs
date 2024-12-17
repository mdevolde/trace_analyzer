use calamine::{open_workbook, Reader, Xlsx};
use chrono::{DateTime, Timelike};
use clap::Parser;
use pcap::Capture;
use plotters::prelude::Palette99;
use plotters::prelude::*;
use pnet;
use std::collections::{BTreeMap, HashMap};

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

    /// Set the verbosity level (default: 1). There are 3 levels of verbosity (0, 1, 2)
    #[arg(short, long, default_value = "1")]
    verbose: i32,

    /// Select one or more devices to analyze (optional, can be repeated)
    #[arg(short, long, num_args = 0.., action = clap::ArgAction::Append)]
    selected_device: Vec<String>,
}

/// Load MAC addresses from an Excel file
fn load_mac_addresses(file: &str, selected_devices: &Vec<String>, verbose: i32) -> HashMap<String, String> {
    let mut workbook: Xlsx<_> = open_workbook(file).expect("Impossible to read the Excel file");
    let mut mac_mapping = HashMap::new();
    let names = workbook.sheet_names().to_owned();

    if verbose > 1 {
        println!("Reading Excel file: {}", file);
    }

    if let Ok(range) = workbook.worksheet_range(&names[0]) {
        for row in range.rows().skip(1) {
            let device = row[1].to_string();
            let mac = row[2].to_string().to_lowercase();
            if !selected_devices.is_empty() {
                if selected_devices.contains(&device) {
                    mac_mapping.insert(mac.clone(), device.clone());
                    if verbose > 1 {
                        println!("Loaded device: {} -> {}", device, mac);
                    }
                }
            } else {
                mac_mapping.insert(mac.clone(), device.clone());
                if verbose > 1 {
                    println!("Loaded device: {} -> {}", device, mac);
                }
            }
        }
    }

    if verbose >= 1 {
        println!("Loaded MAC addresses for {} devices", mac_mapping.len());
    }
    mac_mapping
}

/// Analyze a PCAP file for device activity
fn analyze_pcap(
    pcap_file: &str,
    mac_mapping: &HashMap<String, String>,
    verbose: i32,
) -> BTreeMap<String, Vec<u32>> {
    let mut activity: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    let mut cap = Capture::from_file(pcap_file).expect("Impossible to read the PCAP file");

    if verbose >= 1 {
        println!("Analyzing PCAP file: {}", pcap_file);
    }

    while let Ok(packet) = cap.next_packet() {
        let timestamp = packet.header.ts.tv_sec as i64;
        let time = DateTime::from_timestamp(timestamp, 0).expect("Invalid timestamp");

        let hour = time.hour();

        if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet.data) {
            let src_mac = ethernet.get_source().to_string();
            let dst_mac = ethernet.get_destination().to_string();

            if let Some(device) = mac_mapping.get(&src_mac) {
                activity.entry(device.clone()).or_default().push(hour);
                if verbose > 1 {
                    println!("Device '{}' sent data at hour {}", device, hour);
                }
            }
            if let Some(device) = mac_mapping.get(&dst_mac) {
                activity.entry(device.clone()).or_default().push(hour);
                if verbose > 1 {
                    println!("Device '{}' received data at hour {}", device, hour);
                }
            }
        }
    }

    if verbose >= 1 {
        println!("Finished analyzing PCAP file.");
    }
    activity
}

/// Plot device activity on a 24-hour graph (device usage per hour)
fn plot_device_activity(activity: &BTreeMap<String, Vec<u32>>, output_file: &str) {
    let mut max_activity = 0;
    for hours in activity.values() {
        let mut hour_counts = vec![0; 24];
        for hour in hours {
            hour_counts[*hour as usize] += 1;
        }
        let max_count = *hour_counts.iter().max().unwrap();
        if max_count > max_activity {
            max_activity = max_count;
        }
    }
    let y_max = ((max_activity + 9) / 10) * 10;

    let root = BitMapBackend::new(output_file, (1280, 720)).into_drawing_area();
    root.fill(&WHITE).unwrap();

    let mut chart = ChartBuilder::on(&root)
        .caption("Hours of use of IoT devices", ("sans-serif", 30))
        .margin(5)
        .x_label_area_size(50)
        .y_label_area_size(50)
        .build_cartesian_2d(0..24, 0..y_max)
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

    chart
        .configure_series_labels()
        .border_style(&BLACK)
        .draw()
        .unwrap();
    println!("Generated graph: {}", output_file);
}

fn main() {
    let args = Args::parse();
    let device_file = args.device_file;
    let pcap_file = args.pcap_file;
    let output_file = args.output_file;
    let selected_devices = args.selected_device;
    let verbose = args.verbose;

    if verbose >= 1 {
        println!("Starting analysis...");
    }

    let mac_mapping = load_mac_addresses(&device_file, &selected_devices, verbose);
    let activity = analyze_pcap(&pcap_file, &mac_mapping, verbose);
    plot_device_activity(&activity, &output_file);

    if verbose >= 1 {
        println!("Graph saved to {}", output_file);
    }
}
