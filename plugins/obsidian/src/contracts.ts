export interface StatusShare {
  name: string;
  path: string;
  declared_direction: string;
  server_confirmed_role?: string;
  state: string;
  last_success_at: string | null;
  last_error: string | null;
  bytes_sent_session: number;
  bytes_received_session: number;
  pending_local_changes: number;
}

export interface StatusResponse {
  node: string;
  daemon_uptime_s: number;
  config_version: string;
  shares: StatusShare[];
}

export interface ConflictItem {
  id: number;
  vault_id: string;
  path: string;
  conflict_type: string;
  fork_path: string | null;
  created_at: number;
}

export interface ConflictDiff {
  vault_id: string;
  path: string;
  fork_path: string | null;
  local_content: string;
  local_error: string | null;
  fork_content: string;
  fork_error: string | null;
}

export type ConflictAction =
  | "keep-local"
  | "keep-remote"
  | "fork-local"
  | "fork-remote"
  | "merge";
