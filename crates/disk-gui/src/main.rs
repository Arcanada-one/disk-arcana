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

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Disk Arcana")
        .with_inner_size([720.0, 480.0])
        .with_min_inner_size([480.0, 320.0]);

    // Set the runtime Dock/window icon. Without this, eframe falls back to its
    // built-in default glyph in the Dock even though the bundled `.icns` is
    // valid — the running process advertises its own icon, which wins while the
    // app is open. A load failure is non-fatal: we just keep the default.
    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Disk Arcana",
        options,
        Box::new(move |_cc| Ok(Box::new(gui::DiskGuiApp::new(handle)))),
    )
    .expect("eframe run_native");
}

/// Decode the embedded PNG into an `egui::IconData` for the Dock/window icon.
///
/// The PNG is extracted from the bundled `.icns` (256×256) and compiled into
/// the binary so the icon is available regardless of the working directory or
/// bundle layout. Returns `None` if decoding fails — the caller falls back to
/// eframe's default icon rather than aborting startup.
#[cfg(target_os = "macos")]
fn load_app_icon() -> Option<eframe::egui::IconData> {
    const ICON_PNG: &[u8] = include_bytes!("../assets/icon-256.png");

    let image = image::load_from_memory(ICON_PNG).ok()?.into_rgba8();
    let (width, height) = image.dimensions();
    Some(eframe::egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    })
}
