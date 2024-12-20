use crate::utils::*;
use plotters::prelude::*;

/// Plot device activity on a generic graph
pub fn plot_device_activity_generic<T: IntoIterator<Item = (String, Vec<u32>)>>(
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

/// Plot device activity on a median graph
pub fn plot_device_activity_median(
    hourly_medians: &[u32],
    output_file: &str,
    title: &str,
    device: &str,
) {
    let root = BitMapBackend::new(output_file, (1280, 720)).into_drawing_area();
    root.fill(&WHITE).unwrap();

    let y_max = ((hourly_medians.iter().max().unwrap_or(&0) + 9) / 10) * 10;

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 30))
        .margin(5)
        .x_label_area_size(50)
        .y_label_area_size(50)
        .build_cartesian_2d(0..24, 0..y_max)
        .unwrap();

    chart.configure_mesh().draw().unwrap();

    let color = Palette99::pick(0).to_rgba();

    chart
        .draw_series(LineSeries::new(
            (0..24).map(|h| (h, hourly_medians[h as usize])),
            &color,
        ))
        .unwrap()
        .label(device)
        .legend(move |(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], color.clone()));

    chart
        .configure_series_labels()
        .border_style(&BLACK)
        .draw()
        .unwrap();

    println!("Generated median graph: {}", output_file);
}
