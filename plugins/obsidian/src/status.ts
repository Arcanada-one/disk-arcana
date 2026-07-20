import type { ConflictItem, StatusResponse } from "./contracts";

export type PluginState = "offline" | "synced" | "syncing" | "conflict";

export function derivePluginState(
  status: StatusResponse | null,
  conflicts: ConflictItem[]
): PluginState {
  if (status === null) return "offline";
  if (conflicts.length > 0) return "conflict";
  if (
    status.shares.some(
      (share) => share.state === "syncing" || share.pending_local_changes > 0
    )
  ) {
    return "syncing";
  }
  return "synced";
}

export const STATUS_LABEL: Record<PluginState, string> = {
  offline: "Disk: offline ✗",
  synced: "Disk: synced ✓",
  syncing: "Disk: syncing ⟳",
  conflict: "Disk: conflict ⚠"
};
