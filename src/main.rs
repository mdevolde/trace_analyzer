use calamine::{open_workbook, Reader, Xlsx};
use chrono::{DateTime, Timelike};
use clap::Parser;
use pcap::Capture;
use plotters::prelude::Palette99;
use plotters::prelude::*;
use pnet;
use std::collections::{BTreeMap, HashMap};
use std::fs;

/// Simple tool to analyze device activity in a PCAP file or folder
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Excel file containing the list of devices and their MAC addresses
    #[arg(short, long)]
    device_file: String,

    /// PCAP file to analyze for device activity (mutually exclusive with `pcap_folder`)
    #[arg(short, long, conflicts_with = "pcap_folder")]
    pcap_file: Option<String>,

    /// Folder containing multiple PCAP files to analyze for a single device's activity (mutually exclusive with `pcap_file`)
    #[arg(short = 'P', long, conflicts_with = "pcap_file")]
    pcap_folder: Option<String>,

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
fn load_mac_addresses(
    file: &str,
    selected_devices: &Vec<String>,
    verbose: i32,
) -> HashMap<String, String> {
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

/// Count hourly activity
fn count_hourly_activity(hours: &[u32]) -> Vec<u32> {
    let mut hour_counts = vec![0; 24];
    for &hour in hours {
        hour_counts[hour as usize] += 1;
    }
    hour_counts
}

/// Analyze packets from a PCAP capture
fn analyze_packets<F>(
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

/// Analyze a single PCAP file for device activity
fn analyze_pcap(
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

/// Analyze multiple PCAP files for a single device's activity, distinguishing days
fn analyze_pcap_folder(
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

/// Plot device activity on a generic graph
fn plot_device_activity_generic<T: IntoIterator<Item = (String, Vec<u32>)>>(
    activity: T,
    output_file: &str,
    title: &str,
) {
    let root = BitMapBackend::new(output_file, (1280, 720)).into_drawing_area();
    root.fill(&WHITE).unwrap();

    let activity_vec: Vec<_> = activity.into_iter().collect();
    let max_hourly_activity = activity_vec
        .iter()
        .map(|(_, hours)| count_hourly_activity(&hours))
        .flatten()
        .max()
        .unwrap_or(0);

    let y_max = ((max_hourly_activity + 9) / 10) * 10;

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 30))
        .margin(5)
        .x_label_area_size(50)
        .y_label_area_size(50)
        .build_cartesian_2d(0..24, 0..y_max)
        .unwrap();

    chart.configure_mesh().draw().unwrap();
    for (i, (label, hours)) in activity_vec.into_iter().enumerate() {
        let color = Palette99::pick(i).to_rgba();
        let hour_counts = count_hourly_activity(&hours);

        chart
            .draw_series(LineSeries::new(
                (0..24).map(|h| (h as i32, hour_counts[h])),
                &color,
            ))
            .unwrap()
            .label(label)
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
        let daily_activity = analyze_pcap_folder(&folder, &mac_mapping, verbose);
        plot_device_activity_generic(
            daily_activity.iter().map(|(k, v)| (k.clone(), v.clone())),
            &output_file,
            "Daily Device Activity",
        );
    }

    if verbose >= 1 {
        println!("Graph saved to {}", output_file);
    }
}
