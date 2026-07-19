import { describe, expect, it } from "vitest";
import type { StatusResponse } from "../src/contracts";
import { derivePluginState } from "../src/status";

const status: StatusResponse = {
  node: "test",
  daemon_uptime_s: 1,
  config_version: "v1",
  shares: []
};

describe("derivePluginState", () => {
  it("maps offline and conflict states", () => {
    expect(derivePluginState(null, [])).toBe("offline");
    expect(
      derivePluginState(status, [
        { id: 1, vault_id: "wiki", path: "a.md", conflict_type: "Concurrent", fork_path: null, created_at: 1 }
      ])
    ).toBe("conflict");
  });

  it("maps pending work to syncing and an idle daemon to synced", () => {
    expect(
      derivePluginState(
        {
          ...status,
          shares: [
            {
              name: "wiki",
              path: "/tmp/wiki",
              declared_direction: "bidirectional",
              state: "idle",
              last_success_at: null,
              last_error: null,
              bytes_sent_session: 0,
              bytes_received_session: 0,
              pending_local_changes: 1
            }
          ]
        },
        []
      )
    ).toBe("syncing");
    expect(derivePluginState(status, [])).toBe("synced");
  });
});
