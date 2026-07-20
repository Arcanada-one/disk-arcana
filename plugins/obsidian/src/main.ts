import { Notice, Plugin, requestUrl } from "obsidian";
import { ConflictModal } from "./conflict-modal";
import { DaemonClient } from "./daemon-client";
import {
  DEFAULT_SETTINGS,
  DiskArcanaSettingTab,
  sanitizeSettings,
  type DiskArcanaSettings
} from "./settings";
import { derivePluginState, STATUS_LABEL } from "./status";
import { SyncDebounce } from "./sync-debounce";

export default class DiskArcanaPlugin extends Plugin {
  settings: DiskArcanaSettings = DEFAULT_SETTINGS;
  private statusEl: HTMLElement | null = null;
  private readonly syncDebounce = new SyncDebounce(500, () => void this.sync());
  private lastStatus = "";

  async onload(): Promise<void> {
    this.settings = sanitizeSettings((await this.loadData()) ?? {});
    this.statusEl = this.addStatusBarItem();
    this.statusEl.addClass("disk-arcana-status");
    this.statusEl.addEventListener("click", () => this.openConflicts());
    this.addSettingTab(new DiskArcanaSettingTab(this.app, this));
    this.addCommand({
      id: "open-conflicts",
      name: "Open conflict resolver",
      callback: () => this.openConflicts()
    });
    this.registerEvent(this.app.vault.on("create", () => this.queueSync()));
    this.registerEvent(this.app.vault.on("modify", () => this.queueSync()));
    this.registerEvent(this.app.vault.on("delete", () => this.queueSync()));
    this.registerEvent(this.app.vault.on("rename", () => this.queueSync()));
    await this.refreshStatus();
    this.registerInterval(
      window.setInterval(() => void this.refreshStatus(), this.settings.pollIntervalSeconds * 1000)
    );
  }

  onunload(): void {
    this.syncDebounce.cancel();
  }

  async saveSettings(): Promise<void> {
    this.settings = sanitizeSettings(this.settings);
    await this.saveData(this.settings);
    await this.refreshStatus();
  }

  async reloadConfig(): Promise<void> {
    try {
      await this.client().reloadConfig();
      new Notice("Disk Arcana config reload queued");
    } catch (error) {
      new Notice(`Disk Arcana reload failed: ${message(error)}`);
    }
  }

  private client(): DaemonClient {
    return new DaemonClient(this.settings.daemonUrl, requestUrl);
  }

  private openConflicts(): void {
    new ConflictModal(this.app, this.client(), this.settings.defaultConflictAction).open();
  }

  private queueSync(): void {
    this.syncDebounce.queue();
  }

  private async sync(): Promise<void> {
    await this.client().sync().catch((error: unknown) => {
      if (this.settings.notifications) new Notice(`Disk Arcana sync failed: ${message(error)}`);
    });
  }

  private async refreshStatus(): Promise<void> {
    try {
      const client = this.client();
      const [status, conflicts] = await Promise.all([client.status(), client.conflicts()]);
      const nextStatus = derivePluginState(status, conflicts);
      this.statusEl?.setText(STATUS_LABEL[nextStatus]);
      if (this.settings.notifications && nextStatus === "conflict" && this.lastStatus !== "conflict") {
        new Notice(`${conflicts.length} Disk Arcana conflict${conflicts.length === 1 ? "" : "s"}`);
      }
      if (
        nextStatus === "conflict" &&
        this.lastStatus !== "conflict" &&
        this.settings.conflictStrategy === "manual"
      ) {
        this.openConflicts();
      }
      this.lastStatus = nextStatus;
    } catch {
      this.statusEl?.setText(STATUS_LABEL.offline);
      if (this.settings.notifications && this.lastStatus !== "offline") {
        new Notice("Disk Arcana daemon is offline");
      }
      this.lastStatus = "offline";
    }
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
