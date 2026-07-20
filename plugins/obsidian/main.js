"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => DiskArcanaPlugin
});
module.exports = __toCommonJS(main_exports);
var import_obsidian3 = require("obsidian");

// src/conflict-modal.ts
var import_obsidian = require("obsidian");
var ACTIONS = [
  "keep-local",
  "keep-remote",
  "fork-local",
  "fork-remote",
  "merge"
];
var ConflictModal = class extends import_obsidian.Modal {
  constructor(app, client, defaultAction) {
    super(app);
    this.client = client;
    this.defaultAction = defaultAction;
  }
  async onOpen() {
    this.setTitle("Disk Arcana conflicts");
    this.contentEl.empty();
    try {
      const conflicts = await this.client.conflicts();
      if (conflicts.length === 0) {
        this.contentEl.createEl("p", { text: "No unresolved conflicts." });
        return;
      }
      for (const conflict of conflicts) this.renderConflict(conflict);
    } catch (error) {
      this.contentEl.createEl("p", { text: `Conflicts unavailable: ${message(error)}` });
    }
  }
  renderConflict(conflict) {
    const row = this.contentEl.createDiv({ cls: "disk-arcana-conflict" });
    row.createEl("strong", { text: `${conflict.vault_id}: ${conflict.path}` });
    row.createEl("div", { text: conflict.conflict_type });
    const diff = row.createDiv({ cls: "disk-arcana-diff-grid" });
    const local = diff.createEl("pre", { cls: "disk-arcana-diff" });
    const remote = diff.createEl("pre", { cls: "disk-arcana-diff" });
    local.setText("LOCAL\nSelect \u201CShow diff\u201D to load file contents.");
    remote.setText("REMOTE FORK\nSelect \u201CShow diff\u201D to load file contents.");
    const actions = row.createDiv({ cls: "disk-arcana-conflict-actions" });
    const show = actions.createEl("button", { text: "Show diff" });
    show.addEventListener("click", () => void this.showDiff(conflict, local, remote));
    const orderedActions = [this.defaultAction, ...ACTIONS.filter((action) => action !== this.defaultAction)];
    for (const action of orderedActions) {
      const button = actions.createEl("button", { text: action });
      if (action === this.defaultAction) button.addClass("mod-cta");
      button.addEventListener("click", () => void this.resolve(conflict, action, row));
    }
  }
  async showDiff(conflict, localTarget, remoteTarget) {
    try {
      const diff = await this.client.conflictDiff(conflict.vault_id, conflict.path);
      localTarget.setText(`LOCAL
${diff.local_content}`);
      remoteTarget.setText(`REMOTE FORK
${diff.fork_content}`);
    } catch (error) {
      localTarget.setText(`Diff unavailable: ${message(error)}`);
      remoteTarget.setText("REMOTE FORK\nunavailable");
    }
  }
  async resolve(conflict, action, row) {
    try {
      await this.client.resolve(conflict.vault_id, conflict.path, action);
      row.remove();
      new import_obsidian.Notice(`Resolved ${conflict.path} with ${action}`);
    } catch (error) {
      new import_obsidian.Notice(`Resolution failed: ${message(error)}`);
    }
  }
};
function message(error) {
  return error instanceof Error ? error.message : String(error);
}

// src/daemon-client.ts
function normalizeLoopbackUrl(raw) {
  const url = new URL(raw);
  const loopback = isLoopbackHostname(url.hostname);
  if (url.protocol !== "http:" || !loopback || url.username || url.password) {
    throw new Error("Daemon URL must be an unauthenticated HTTP loopback address");
  }
  if (url.pathname !== "/" || url.search || url.hash) {
    throw new Error("Daemon URL must not include a path, query, or fragment");
  }
  return url.origin;
}
function isLoopbackHostname(hostname) {
  if (hostname === "localhost" || hostname === "::1" || hostname === "[::1]") return true;
  const octets = hostname.split(".");
  return octets.length === 4 && octets[0] === "127" && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}
var DaemonClient = class {
  constructor(baseUrl, request) {
    this.request = request;
    this.baseUrl = normalizeLoopbackUrl(baseUrl);
  }
  baseUrl;
  status() {
    return this.json("GET", "/status");
  }
  conflicts() {
    return this.json("GET", "/conflicts");
  }
  conflictDiff(vaultId, path) {
    return this.json(
      "GET",
      `/conflicts/${encodeURIComponent(vaultId)}/${encodeURIComponent(path)}/diff`
    );
  }
  async resolve(vaultId, path, action) {
    await this.json(
      "POST",
      `/conflicts/${encodeURIComponent(vaultId)}/${encodeURIComponent(path)}`,
      { action }
    );
  }
  async sync() {
    await this.json("POST", "/sync");
  }
  async reloadConfig() {
    await this.json("POST", "/config/reload");
  }
  async json(method, path, body) {
    const response = await this.request({
      url: `${this.baseUrl}${path}`,
      method,
      contentType: body === void 0 ? void 0 : "application/json",
      body: body === void 0 ? void 0 : JSON.stringify(body),
      throw: false
    });
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Disk Arcana daemon returned HTTP ${response.status}`);
    }
    return response.json;
  }
};

// src/settings.ts
var import_obsidian2 = require("obsidian");

// src/settings-model.ts
var CONFLICT_ACTIONS = [
  "keep-local",
  "keep-remote",
  "fork-local",
  "fork-remote",
  "merge"
];
var DEFAULT_SETTINGS = {
  daemonUrl: "http://127.0.0.1:9444",
  pollIntervalSeconds: 5,
  defaultConflictAction: "fork-remote",
  conflictStrategy: "manual",
  notifications: true
};
function sanitizeSettings(input) {
  let daemonUrl = DEFAULT_SETTINGS.daemonUrl;
  try {
    daemonUrl = normalizeLoopbackUrl(input.daemonUrl ?? daemonUrl);
  } catch {
  }
  const interval = Number(input.pollIntervalSeconds);
  const pollIntervalSeconds = Number.isFinite(interval) ? Math.min(300, Math.max(2, Math.round(interval))) : DEFAULT_SETTINGS.pollIntervalSeconds;
  const defaultConflictAction = CONFLICT_ACTIONS.includes(input.defaultConflictAction) ? input.defaultConflictAction : DEFAULT_SETTINGS.defaultConflictAction;
  const conflictStrategy = input.conflictStrategy === "auto-fork" ? "auto-fork" : "manual";
  return {
    ...DEFAULT_SETTINGS,
    ...input,
    daemonUrl,
    pollIntervalSeconds,
    defaultConflictAction,
    conflictStrategy
  };
}

// src/settings.ts
var DiskArcanaSettingTab = class extends import_obsidian2.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }
  display() {
    this.containerEl.empty();
    new import_obsidian2.Setting(this.containerEl).setName("Daemon URL").setDesc("Loopback-only Disk Arcana REST endpoint").addText(
      (text) => text.setValue(this.plugin.settings.daemonUrl).onChange(async (value) => {
        this.plugin.settings.daemonUrl = normalizeLoopbackUrl(value);
        await this.plugin.saveSettings();
      })
    );
    new import_obsidian2.Setting(this.containerEl).setName("Status polling interval").setDesc("Seconds between daemon status checks (2\u2013300)").addText(
      (text) => text.setValue(String(this.plugin.settings.pollIntervalSeconds)).onChange(async (value) => {
        this.plugin.settings = sanitizeSettings({ ...this.plugin.settings, pollIntervalSeconds: Number(value) });
        await this.plugin.saveSettings();
      })
    );
    new import_obsidian2.Setting(this.containerEl).setName("Conflict strategy").setDesc("Manual opens the resolver; auto-fork leaves the daemon fork in place and only notifies").addDropdown(
      (dropdown) => dropdown.addOptions({ manual: "Manual resolution", "auto-fork": "Auto-fork and notify" }).setValue(this.plugin.settings.conflictStrategy).onChange(async (value) => {
        this.plugin.settings.conflictStrategy = value === "auto-fork" ? "auto-fork" : "manual";
        await this.plugin.saveSettings();
      })
    );
    new import_obsidian2.Setting(this.containerEl).setName("Default conflict action").setDesc("Shown first in the conflict resolver; every action still requires a click").addDropdown(
      (dropdown) => dropdown.addOptions({
        "fork-remote": "Fork remote",
        "fork-local": "Fork local",
        "keep-local": "Keep local",
        "keep-remote": "Keep remote",
        merge: "Merge"
      }).setValue(this.plugin.settings.defaultConflictAction).onChange(async (value) => {
        this.plugin.settings.defaultConflictAction = value;
        await this.plugin.saveSettings();
      })
    );
    new import_obsidian2.Setting(this.containerEl).setName("Show notifications").addToggle(
      (toggle) => toggle.setValue(this.plugin.settings.notifications).onChange(async (value) => {
        this.plugin.settings.notifications = value;
        await this.plugin.saveSettings();
      })
    );
    new import_obsidian2.Setting(this.containerEl).setName("Reload daemon config").setDesc("Ask the running daemon to reload disk.toml").addButton((button) => button.setButtonText("Reload").onClick(() => this.plugin.reloadConfig()));
  }
};

// src/status.ts
function derivePluginState(status, conflicts) {
  if (status === null) return "offline";
  if (conflicts.length > 0) return "conflict";
  if (status.shares.some(
    (share) => share.state === "syncing" || share.pending_local_changes > 0
  )) {
    return "syncing";
  }
  return "synced";
}
var STATUS_LABEL = {
  offline: "Disk: offline \u2717",
  synced: "Disk: synced \u2713",
  syncing: "Disk: syncing \u27F3",
  conflict: "Disk: conflict \u26A0"
};

// src/sync-debounce.ts
var SyncDebounce = class {
  constructor(delayMs, callback) {
    this.delayMs = delayMs;
    this.callback = callback;
  }
  timer = null;
  queue() {
    this.cancel();
    this.timer = setTimeout(() => {
      this.timer = null;
      this.callback();
    }, this.delayMs);
  }
  cancel() {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }
};

// src/main.ts
var DiskArcanaPlugin = class extends import_obsidian3.Plugin {
  settings = DEFAULT_SETTINGS;
  statusEl = null;
  syncDebounce = new SyncDebounce(500, () => void this.sync());
  lastStatus = "";
  async onload() {
    this.settings = sanitizeSettings(await this.loadData() ?? {});
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
      window.setInterval(() => void this.refreshStatus(), this.settings.pollIntervalSeconds * 1e3)
    );
  }
  onunload() {
    this.syncDebounce.cancel();
  }
  async saveSettings() {
    this.settings = sanitizeSettings(this.settings);
    await this.saveData(this.settings);
    await this.refreshStatus();
  }
  async reloadConfig() {
    try {
      await this.client().reloadConfig();
      new import_obsidian3.Notice("Disk Arcana config reload queued");
    } catch (error) {
      new import_obsidian3.Notice(`Disk Arcana reload failed: ${message2(error)}`);
    }
  }
  client() {
    return new DaemonClient(this.settings.daemonUrl, import_obsidian3.requestUrl);
  }
  openConflicts() {
    new ConflictModal(this.app, this.client(), this.settings.defaultConflictAction).open();
  }
  queueSync() {
    this.syncDebounce.queue();
  }
  async sync() {
    await this.client().sync().catch((error) => {
      if (this.settings.notifications) new import_obsidian3.Notice(`Disk Arcana sync failed: ${message2(error)}`);
    });
  }
  async refreshStatus() {
    try {
      const client = this.client();
      const [status, conflicts] = await Promise.all([client.status(), client.conflicts()]);
      const nextStatus = derivePluginState(status, conflicts);
      this.statusEl?.setText(STATUS_LABEL[nextStatus]);
      if (this.settings.notifications && nextStatus === "conflict" && this.lastStatus !== "conflict") {
        new import_obsidian3.Notice(`${conflicts.length} Disk Arcana conflict${conflicts.length === 1 ? "" : "s"}`);
      }
      if (nextStatus === "conflict" && this.lastStatus !== "conflict" && this.settings.conflictStrategy === "manual") {
        this.openConflicts();
      }
      this.lastStatus = nextStatus;
    } catch {
      this.statusEl?.setText(STATUS_LABEL.offline);
      if (this.settings.notifications && this.lastStatus !== "offline") {
        new import_obsidian3.Notice("Disk Arcana daemon is offline");
      }
      this.lastStatus = "offline";
    }
  }
};
function message2(error) {
  return error instanceof Error ? error.message : String(error);
}
