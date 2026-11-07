#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

mod gui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 720.0])
            .with_min_inner_size([860.0, 600.0])
            .with_title("Static IP Manager"),
        ..Default::default()
    };
    eframe::run_native(
        "Static IP Manager",
        options,
        Box::new(|cc| {
            gui::apply_style(&cc.egui_ctx);
            Ok(Box::new(gui::App::new()))
        }),
    )
}
