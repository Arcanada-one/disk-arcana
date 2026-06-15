//! macOS-only: eframe application state and egui rendering.
//!
//! This module is compiled ONLY when `target_os = "macos"`. It requires
//! the `eframe` crate which is listed under
//! `[target.'cfg(target_os = "macos")'.dependencies]`.

use std::time::{Duration, Instant};

use anyhow::Result;
use disk_client::StatusResponse;
use eframe::egui;
use tracing::error;

use disk_gui::settings::GuiSettings;
use disk_gui::{format_status, StatusDisplay};

/// How often the GUI polls the daemon REST endpoint.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Internal state of the settings panel during editing.
#[derive(Clone)]
struct SettingsEdit {
    host: String,
    port_str: String,
    storage_path: String,
    port_error: Option<String>,
}

impl SettingsEdit {
    fn from_settings(s: &GuiSettings) -> Self {
        Self {
            host: s.daemon_host.clone(),
            port_str: s.daemon_port.to_string(),
            storage_path: s.storage_path_display.clone(),
            port_error: None,
        }
    }

    fn try_apply(&mut self, target: &mut GuiSettings) -> bool {
        match self.port_str.trim().parse::<u16>() {
            Ok(p) => {
                target.daemon_host = self.host.clone();
                target.daemon_port = p;
                target.storage_path_display = self.storage_path.clone();
                self.port_error = None;
                true
            }
            Err(_) => {
                self.port_error = Some("Port must be a number between 1 and 65535".to_string());
                false
            }
        }
    }
}

/// Main application state.
pub struct DiskGuiApp {
    settings: GuiSettings,
    /// Last successfully received daemon status.
    last_status: Option<StatusDisplay>,
    /// Last poll error message (shown when daemon is unreachable).
    last_error: Option<String>,
    /// Timestamp of the last completed poll attempt.
    last_poll: Option<Instant>,
    /// Pending async status fetch.
    pending_rx: Option<tokio::sync::oneshot::Receiver<Result<StatusResponse>>>,
    /// Whether the settings panel is open.
    settings_open: bool,
    /// Editable copy of settings (used while the panel is open).
    settings_edit: Option<SettingsEdit>,
    /// Tokio runtime for spawning async tasks inside the sync eframe callback.
    rt: tokio::runtime::Handle,
}

impl DiskGuiApp {
    pub fn new(rt: tokio::runtime::Handle) -> Self {
        Self {
            settings: GuiSettings::load_or_default(),
            last_status: None,
            last_error: None,
            last_poll: None,
            pending_rx: None,
            settings_open: false,
            settings_edit: None,
            rt,
        }
    }

    /// Kick off an async status fetch if no fetch is already in flight and
    /// the poll interval has elapsed (or no poll has happened yet).
    fn maybe_poll(&mut self, ctx: &egui::Context) {
        if self.pending_rx.is_some() {
            return;
        }
        let should_poll = match self.last_poll {
            None => true,
            Some(t) => t.elapsed() >= POLL_INTERVAL,
        };
        if !should_poll {
            return;
        }

        let (tx, rx) = tokio::sync::oneshot::channel();
        let host = self.settings.daemon_host.clone();
        let port = self.settings.daemon_port;
        let ctx2 = ctx.clone();

        self.rt.spawn(async move {
            let result = disk_gui::fetch_status(&host, port).await;
            let _ = tx.send(result);
            ctx2.request_repaint();
        });

        self.pending_rx = Some(rx);
        self.last_poll = Some(Instant::now());
        // Schedule a repaint so the UI updates when the result arrives.
        ctx.request_repaint_after(POLL_INTERVAL);
    }

    /// Drain the pending receiver if a result has arrived.
    fn drain_pending(&mut self) {
        if let Some(rx) = &mut self.pending_rx {
            match rx.try_recv() {
                Ok(Ok(resp)) => {
                    self.last_status = Some(format_status(&resp));
                    self.last_error = None;
                    self.pending_rx = None;
                }
                Ok(Err(e)) => {
                    self.last_status = None;
                    self.last_error = Some(format!("{e:#}"));
                    self.pending_rx = None;
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                    // Still in flight.
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    self.last_error = Some("status fetch dropped".to_string());
                    self.pending_rx = None;
                }
            }
        }
    }
}

impl eframe::App for DiskGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_pending();
        self.maybe_poll(ctx);

        // Top panel — menu bar.
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Disk Arcana");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Settings").clicked() {
                        self.settings_open = !self.settings_open;
                        if self.settings_open {
                            self.settings_edit = Some(SettingsEdit::from_settings(&self.settings));
                        }
                    }
                });
            });
        });

        // Bottom status bar.
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                match &self.last_error {
                    Some(e) => {
                        ui.colored_label(egui::Color32::RED, "●");
                        ui.label(format!(
                            "daemon not reachable at {}:{} — {e}",
                            self.settings.daemon_host, self.settings.daemon_port
                        ));
                    }
                    None => {
                        if self.last_status.is_some() {
                            ui.colored_label(egui::Color32::GREEN, "●");
                            ui.label("daemon connected");
                        } else {
                            ui.colored_label(egui::Color32::GRAY, "●");
                            ui.label("connecting…");
                        }
                    }
                }
                if self.pending_rx.is_some() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label("polling…");
                    });
                }
            });
        });

        // Settings modal window.
        // We collect button intents into locals to avoid nested mutable borrows.
        let mut do_save = false;
        let mut do_cancel = false;
        if self.settings_open {
            let mut open = self.settings_open;
            egui::Window::new("Settings")
                .open(&mut open)
                .resizable(false)
                .collapsible(false)
                .show(ctx, |ui| {
                    if let Some(edit) = &mut self.settings_edit {
                        egui::Grid::new("settings_grid")
                            .num_columns(2)
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
                                ui.label("Daemon host:");
                                ui.text_edit_singleline(&mut edit.host);
                                ui.end_row();

                                ui.label("Daemon port:");
                                ui.text_edit_singleline(&mut edit.port_str);
                                ui.end_row();

                                ui.label("Storage path:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut edit.storage_path)
                                        .hint_text("(read-only display)"),
                                );
                                ui.end_row();
                            });

                        if let Some(err) = &edit.port_error {
                            ui.colored_label(egui::Color32::RED, err);
                        }

                        ui.separator();
                        ui.horizontal(|ui| {
                            if ui.button("Save").clicked() {
                                do_save = true;
                            }
                            if ui.button("Cancel").clicked() {
                                do_cancel = true;
                            }
                        });
                    }
                });
            self.settings_open = open;
        }
        // Process Save/Cancel after the window closure to avoid nested borrows.
        if do_save {
            if let Some(edit) = &mut self.settings_edit {
                let mut tmp = self.settings.clone();
                if edit.try_apply(&mut tmp) {
                    self.settings = tmp;
                    if let Err(err) = self.settings.save() {
                        error!("failed to save settings: {err:#}");
                    }
                    self.settings_open = false;
                    self.last_poll = None;
                    self.settings_edit = None;
                }
            }
        }
        if do_cancel {
            self.settings_open = false;
            self.settings_edit = None;
        }

        // Main central panel.
        egui::CentralPanel::default().show(ctx, |ui| {
            match &self.last_status {
                None => {
                    ui.centered_and_justified(|ui| {
                        if self.last_error.is_some() {
                            ui.label(egui::RichText::new("daemon not running").size(20.0));
                        } else {
                            ui.label(egui::RichText::new("connecting to daemon…").size(20.0));
                        }
                    });
                }
                Some(status) => {
                    // Daemon info.
                    egui::Grid::new("daemon_info")
                        .num_columns(2)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("Node:").strong());
                            ui.label(&status.node);
                            ui.end_row();

                            ui.label(egui::RichText::new("Uptime:").strong());
                            ui.label(&status.daemon_uptime);
                            ui.end_row();

                            ui.label(egui::RichText::new("Config:").strong());
                            ui.label(&status.config_version);
                            ui.end_row();
                        });

                    ui.separator();
                    ui.label(egui::RichText::new("Shares").strong().size(16.0));

                    if status.shares.is_empty() {
                        ui.label("No shares configured.");
                    } else {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for share in &status.shares {
                                egui::Frame::group(ui.style()).show(ui, |ui| {
                                    ui.label(egui::RichText::new(&share.name).strong());
                                    ui.label(format!("Path: {}", share.path));
                                    ui.label(format!(
                                        "Direction: {}  State: {}",
                                        share.direction, share.state
                                    ));
                                    if share.pending_changes > 0 {
                                        ui.label(format!(
                                            "Pending: {} change(s)",
                                            share.pending_changes
                                        ));
                                    }
                                    if let Some(ts) = &share.last_success_at {
                                        ui.label(format!("Last sync: {ts}"));
                                    }
                                    if let Some(err) = &share.last_error {
                                        ui.colored_label(
                                            egui::Color32::LIGHT_RED,
                                            format!("Error: {err}"),
                                        );
                                    }
                                });
                                ui.add_space(4.0);
                            }
                        });
                    }
                }
            }
        });
    }
}
