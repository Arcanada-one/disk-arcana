import { App, PluginSettingTab, Setting } from "obsidian";
import type DiskArcanaPlugin from "./main";
import { normalizeLoopbackUrl } from "./daemon-client";
import { sanitizeSettings } from "./settings-model";
import type { ConflictAction } from "./contracts";

export { DEFAULT_SETTINGS, sanitizeSettings, type DiskArcanaSettings } from "./settings-model";

export class DiskArcanaSettingTab extends PluginSettingTab {
  constructor(app: App, private readonly plugin: DiskArcanaPlugin) {
    super(app, plugin);
  }

  display(): void {
    this.containerEl.empty();
    new Setting(this.containerEl)
      .setName("Daemon URL")
      .setDesc("Loopback-only Disk Arcana REST endpoint")
      .addText((text) =>
        text.setValue(this.plugin.settings.daemonUrl).onChange(async (value) => {
          this.plugin.settings.daemonUrl = normalizeLoopbackUrl(value);
          await this.plugin.saveSettings();
        })
      );
    new Setting(this.containerEl)
      .setName("Status polling interval")
      .setDesc("Seconds between daemon status checks (2–300)")
      .addText((text) =>
        text.setValue(String(this.plugin.settings.pollIntervalSeconds)).onChange(async (value) => {
          this.plugin.settings = sanitizeSettings({ ...this.plugin.settings, pollIntervalSeconds: Number(value) });
          await this.plugin.saveSettings();
        })
      );
    new Setting(this.containerEl)
      .setName("Conflict strategy")
      .setDesc("Manual opens the resolver; auto-fork leaves the daemon fork in place and only notifies")
      .addDropdown((dropdown) =>
        dropdown
          .addOptions({ manual: "Manual resolution", "auto-fork": "Auto-fork and notify" })
          .setValue(this.plugin.settings.conflictStrategy)
          .onChange(async (value) => {
            this.plugin.settings.conflictStrategy = value === "auto-fork" ? "auto-fork" : "manual";
            await this.plugin.saveSettings();
          })
      );
    new Setting(this.containerEl)
      .setName("Default conflict action")
      .setDesc("Shown first in the conflict resolver; every action still requires a click")
      .addDropdown((dropdown) =>
        dropdown
          .addOptions({
            "fork-remote": "Fork remote",
            "fork-local": "Fork local",
            "keep-local": "Keep local",
            "keep-remote": "Keep remote",
            merge: "Merge"
          })
          .setValue(this.plugin.settings.defaultConflictAction)
          .onChange(async (value) => {
            this.plugin.settings.defaultConflictAction = value as ConflictAction;
            await this.plugin.saveSettings();
          })
      );
    new Setting(this.containerEl)
      .setName("Show notifications")
      .addToggle((toggle) =>
        toggle.setValue(this.plugin.settings.notifications).onChange(async (value) => {
          this.plugin.settings.notifications = value;
          await this.plugin.saveSettings();
        })
      );
    new Setting(this.containerEl)
      .setName("Reload daemon config")
      .setDesc("Ask the running daemon to reload disk.toml")
      .addButton((button) => button.setButtonText("Reload").onClick(() => this.plugin.reloadConfig()));
  }
}
