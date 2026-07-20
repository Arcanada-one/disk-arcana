import { normalizeLoopbackUrl } from "./daemon-client";
import type { ConflictAction } from "./contracts";

const CONFLICT_ACTIONS: readonly ConflictAction[] = [
  "keep-local",
  "keep-remote",
  "fork-local",
  "fork-remote",
  "merge"
];

export interface DiskArcanaSettings {
  daemonUrl: string;
  pollIntervalSeconds: number;
  defaultConflictAction: ConflictAction;
  conflictStrategy: "auto-fork" | "manual";
  notifications: boolean;
}

export const DEFAULT_SETTINGS: DiskArcanaSettings = {
  daemonUrl: "http://127.0.0.1:9444",
  pollIntervalSeconds: 5,
  defaultConflictAction: "fork-remote",
  conflictStrategy: "manual",
  notifications: true
};

export function sanitizeSettings(input: Partial<DiskArcanaSettings>): DiskArcanaSettings {
  let daemonUrl = DEFAULT_SETTINGS.daemonUrl;
  try {
    daemonUrl = normalizeLoopbackUrl(input.daemonUrl ?? daemonUrl);
  } catch {
    // Fail closed to the canonical loopback endpoint.
  }
  const interval = Number(input.pollIntervalSeconds);
  const pollIntervalSeconds = Number.isFinite(interval)
    ? Math.min(300, Math.max(2, Math.round(interval)))
    : DEFAULT_SETTINGS.pollIntervalSeconds;
  const defaultConflictAction = CONFLICT_ACTIONS.includes(input.defaultConflictAction as ConflictAction)
    ? (input.defaultConflictAction as ConflictAction)
    : DEFAULT_SETTINGS.defaultConflictAction;
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
