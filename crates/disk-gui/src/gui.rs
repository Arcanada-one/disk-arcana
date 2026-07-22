//! macOS-only: eframe application state and egui rendering.
//!
//! This module is compiled ONLY when `target_os = "macos"`. It requires
//! the `eframe` crate which is listed under
//! `[target.'cfg(target_os = "macos")'.dependencies]`.

use std::time::{Duration, Instant};

use anyhow::Result;
use disk_client::{ConflictListItem, StatusResponse};
use eframe::egui;
use tracing::error;

use disk_gui::settings::GuiSettings;
use disk_gui::{format_status, StatusDisplay};

/// How often the GUI polls the daemon REST endpoint.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Resolution actions offered by the conflict modal, paired with the
/// REST `action` string accepted by `POST /conflicts/{path}`.
const CONFLICT_ACTIONS: &[(&str, &str)] = &[
    ("Keep Local", "keep-local"),
    ("Keep Remote", "keep-remote"),
    ("Keep Both (fork)", "fork-local"),
];

type ConflictResolveKey = (String, String);
type ConflictResolveRx = tokio::sync::oneshot::Receiver<(ConflictResolveKey, Result<()>)>;

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
    /// Whether the conflicts panel is open.
    conflicts_open: bool,
    /// Last successfully fetched conflict list.
    conflicts: Vec<ConflictListItem>,
    /// Last conflict-fetch error message.
    conflicts_error: Option<String>,
    /// Pending async conflicts-list fetch.
    conflicts_rx: Option<tokio::sync::oneshot::Receiver<Result<Vec<ConflictListItem>>>>,
    /// Pending async conflict-resolve call: ((vault, path), result).
    resolve_rx: Option<ConflictResolveRx>,
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
            conflicts_open: false,
            conflicts: Vec::new(),
            conflicts_error: None,
            conflicts_rx: None,
            resolve_rx: None,
            rt,
        }
    }

    /// Kick off an async conflicts-list fetch if none is already in flight.
    fn refresh_conflicts(&mut self, ctx: &egui::Context) {
        if self.conflicts_rx.is_some() {
            return;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let host = self.settings.daemon_host.clone();
        let port = self.settings.daemon_port;
        let ctx2 = ctx.clone();

        self.rt.spawn(async move {
            let result = disk_gui::fetch_conflicts(&host, port).await;
            let _ = tx.send(result);
            ctx2.request_repaint();
        });

        self.conflicts_rx = Some(rx);
    }

    /// Drain the pending conflicts-list fetch, if any result has arrived.
    fn drain_conflicts(&mut self) {
        if let Some(rx) = &mut self.conflicts_rx {
            match rx.try_recv() {
                Ok(Ok(items)) => {
                    self.conflicts = items;
                    self.conflicts_error = None;
                    self.conflicts_rx = None;
                }
                Ok(Err(e)) => {
                    self.conflicts_error = Some(format!("{e:#}"));
                    self.conflicts_rx = None;
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    self.conflicts_error = Some("conflicts fetch dropped".to_string());
                    self.conflicts_rx = None;
                }
            }
        }
    }

    /// Kick off an async resolve call for `path` with `action`.
    fn start_resolve_conflict(
        &mut self,
        ctx: &egui::Context,
        vault_id: String,
        path: String,
        action: &'static str,
    ) {
        if self.resolve_rx.is_some() {
            // A resolve is already in flight — ignore extra clicks until it lands.
            return;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let host = self.settings.daemon_host.clone();
        let port = self.settings.daemon_port;
        let ctx2 = ctx.clone();
        let vault2 = vault_id.clone();
        let path2 = path.clone();

        self.rt.spawn(async move {
            let result = disk_gui::resolve_conflict(&host, port, &vault2, &path2, action).await;
            let _ = tx.send(((vault2, path2), result));
            ctx2.request_repaint();
        });

        self.resolve_rx = Some(rx);
    }

    /// Drain the pending resolve call, if a result has arrived.
    ///
    /// On success, the resolved path is removed from the locally cached
    /// conflict list immediately (so the UI updates without waiting for the
    /// next fetch); a full refresh is also kicked off to reconcile state.
    fn drain_resolve(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &mut self.resolve_rx {
            match rx.try_recv() {
                Ok(((vault_id, path), Ok(()))) => {
                    self.conflicts
                        .retain(|c| c.vault_id != vault_id || c.path != path);
                    self.conflicts_error = None;
                    self.resolve_rx = None;
                    self.refresh_conflicts(ctx);
                }
                Ok((_, Err(e))) => {
                    self.conflicts_error = Some(format!("{e:#}"));
                    self.resolve_rx = None;
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    self.conflicts_error = Some("resolve call dropped".to_string());
                    self.resolve_rx = None;
                }
            }
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

    /// Top menu bar — heading, Settings, Conflicts buttons.
    fn render_top_bar(&mut self, ctx: &egui::Context) {
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
                    let conflicts_label = if self.conflicts.is_empty() {
                        "Conflicts".to_string()
                    } else {
                        format!("Conflicts ({})", self.conflicts.len())
                    };
                    if ui.button(conflicts_label).clicked() {
                        self.conflicts_open = !self.conflicts_open;
                        if self.conflicts_open {
                            self.refresh_conflicts(ctx);
                        }
                    }
                });
            });
        });
    }

    /// Bottom status bar — daemon connection indicator.
    fn render_status_bar(&mut self, ctx: &egui::Context) {
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
    }

    /// Settings modal — returns `(save_clicked, cancel_clicked)`.
    fn render_settings_modal(&mut self, ctx: &egui::Context) -> (bool, bool) {
        let mut do_save = false;
        let mut do_cancel = false;
        if !self.settings_open {
            return (do_save, do_cancel);
        }

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
        (do_save, do_cancel)
    }

    fn apply_settings_save(&mut self) {
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

    fn apply_settings_cancel(&mut self) {
        self.settings_open = false;
        self.settings_edit = None;
    }

    /// Conflicts modal — returns `(vault_id, path, action)` when user picks a resolution.
    fn render_conflicts_modal(
        &mut self,
        ctx: &egui::Context,
    ) -> Option<(String, String, &'static str)> {
        let mut do_resolve: Option<(String, String, &'static str)> = None;
        if !self.conflicts_open {
            return do_resolve;
        }

        let mut open = self.conflicts_open;
        egui::Window::new("Conflicts")
            .open(&mut open)
            .resizable(true)
            .default_width(480.0)
            .show(ctx, |ui| {
                if let Some(err) = &self.conflicts_error {
                    ui.colored_label(egui::Color32::RED, err);
                }
                if self.conflicts_rx.is_some() {
                    ui.label("refreshing…");
                }
                if self.conflicts.is_empty() && self.conflicts_rx.is_none() {
                    ui.label("no unresolved conflicts");
                } else {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for item in &self.conflicts {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{}: {}",
                                        item.vault_id, item.path
                                    ))
                                    .strong(),
                                );
                                ui.label(format!("Type: {}", item.conflict_type));
                                if let Some(fork) = &item.fork_path {
                                    ui.label(format!("Fork: {fork}"));
                                }
                                ui.horizontal(|ui| {
                                    for (label, action) in CONFLICT_ACTIONS {
                                        if ui.button(*label).clicked() {
                                            do_resolve = Some((
                                                item.vault_id.clone(),
                                                item.path.clone(),
                                                *action,
                                            ));
                                        }
                                    }
                                });
                            });
                            ui.add_space(4.0);
                        }
                    });
                }
            });
        self.conflicts_open = open;
        do_resolve
    }

    /// Main central panel — daemon status and share list.
    fn render_central_panel(&self, ui: &mut egui::Ui) {
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
    }
}

impl eframe::App for DiskGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_pending();
        self.maybe_poll(ctx);
        self.drain_conflicts();
        self.drain_resolve(ctx);

        self.render_top_bar(ctx);
        self.render_status_bar(ctx);

        let (do_save, do_cancel) = self.render_settings_modal(ctx);
        if do_save {
            self.apply_settings_save();
        }
        if do_cancel {
            self.apply_settings_cancel();
        }

        if let Some((vault_id, path, action)) = self.render_conflicts_modal(ctx) {
            self.start_resolve_conflict(ctx, vault_id, path, action);
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_central_panel(ui);
        });
    }
}
