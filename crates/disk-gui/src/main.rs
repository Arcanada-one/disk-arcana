//! disk-gui binary entrypoint.
//!
//! On macOS: launches the eframe window.
//! On other platforms: the binary still compiles (via the cross-platform
//! lib portions) but exits with an informational message — the windowing
//! stack is not available outside macOS.

#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
mod gui;

fn main() {
    #[cfg(target_os = "macos")]
    {
        run_macos();
    }

    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("disk-gui: macOS only — windowing stack not available on this platform.");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn run_macos() {
    use eframe::egui;

    // Initialise tracing subscriber (stdout, respects RUST_LOG).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Build a shared tokio runtime that the GUI's async tasks will use.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let handle = rt.handle().clone();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Disk Arcana")
            .with_inner_size([720.0, 480.0])
            .with_min_inner_size([480.0, 320.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Disk Arcana",
        options,
        Box::new(move |_cc| Ok(Box::new(gui::DiskGuiApp::new(handle)))),
    )
    .expect("eframe run_native");
}
