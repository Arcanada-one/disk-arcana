import { Modal, Notice } from "obsidian";
import type { DaemonClient } from "./daemon-client";
import type { ConflictAction, ConflictItem } from "./contracts";

const ACTIONS: ConflictAction[] = [
  "keep-local",
  "keep-remote",
  "fork-local",
  "fork-remote",
  "merge"
];

export class ConflictModal extends Modal {
  constructor(
    app: ConstructorParameters<typeof Modal>[0],
    private readonly client: DaemonClient,
    private readonly defaultAction: ConflictAction
  ) {
    super(app);
  }

  async onOpen(): Promise<void> {
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

  private renderConflict(conflict: ConflictItem): void {
    const row = this.contentEl.createDiv({ cls: "disk-arcana-conflict" });
    row.createEl("strong", { text: `${conflict.vault_id}: ${conflict.path}` });
    row.createEl("div", { text: conflict.conflict_type });
    const diff = row.createDiv({ cls: "disk-arcana-diff-grid" });
    const local = diff.createEl("pre", { cls: "disk-arcana-diff" });
    const remote = diff.createEl("pre", { cls: "disk-arcana-diff" });
    local.setText("LOCAL\nSelect “Show diff” to load file contents.");
    remote.setText("REMOTE FORK\nSelect “Show diff” to load file contents.");
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

  private async showDiff(
    conflict: ConflictItem,
    localTarget: HTMLElement,
    remoteTarget: HTMLElement
  ): Promise<void> {
    try {
      const diff = await this.client.conflictDiff(conflict.vault_id, conflict.path);
      localTarget.setText(`LOCAL\n${diff.local_content}`);
      remoteTarget.setText(`REMOTE FORK\n${diff.fork_content}`);
    } catch (error) {
      localTarget.setText(`Diff unavailable: ${message(error)}`);
      remoteTarget.setText("REMOTE FORK\nunavailable");
    }
  }

  private async resolve(
    conflict: ConflictItem,
    action: ConflictAction,
    row: HTMLElement
  ): Promise<void> {
    try {
      await this.client.resolve(conflict.vault_id, conflict.path, action);
      row.remove();
      new Notice(`Resolved ${conflict.path} with ${action}`);
    } catch (error) {
      new Notice(`Resolution failed: ${message(error)}`);
    }
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
