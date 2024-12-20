use calamine::{open_workbook, Reader, Xlsx};
use std::collections::HashMap;

/// Load MAC addresses from an Excel file
pub fn load_mac_addresses(
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
