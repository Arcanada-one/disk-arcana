import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const statusEl = {
    addClass: vi.fn(),
    addEventListener: vi.fn(),
    setText: vi.fn()
  };
  return {
    statusEl,
    addSettingTab: vi.fn(),
    addCommand: vi.fn(),
    vaultOn: vi.fn((_event: string, _callback: () => void) => ({})),
    modalOpen: vi.fn(),
    notice: vi.fn(),
    requestUrl: vi.fn(async ({ url }: { url: string }): Promise<{ status: number; json: unknown }> => ({
      status: 200,
      json: url.endsWith("/conflicts") ? [] : { node: "test", shares: [] }
    }))
  };
});

vi.mock("obsidian", () => ({
  Notice: class {
    constructor(message: string) {
      mocks.notice(message);
    }
  },
  Plugin: class {
    app = { vault: { on: mocks.vaultOn } };
    loadData = vi.fn(async () => ({}));
    saveData = vi.fn(async () => undefined);
    addStatusBarItem = vi.fn(() => mocks.statusEl);
    addSettingTab = mocks.addSettingTab;
    addCommand = mocks.addCommand;
    registerEvent = vi.fn();
    registerInterval = vi.fn();
  },
  PluginSettingTab: class {},
  Setting: class {},
  Modal: class {
    contentEl = {};
    open = mocks.modalOpen;
  },
  requestUrl: mocks.requestUrl
}));

import DiskArcanaPlugin from "../src/main";

describe("DiskArcanaPlugin surfaces", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("window", { setInterval: vi.fn(() => 1) });
    mocks.requestUrl.mockImplementation(async ({ url }: { url: string }) => ({
      status: 200,
      json: url.endsWith("/conflicts") ? [] : { node: "test", shares: [] }
    }));
  });

  it("registers settings, status, conflict command, and every vault event", async () => {
    const plugin = new DiskArcanaPlugin({} as never, {} as never);
    await plugin.onload();

    expect(mocks.addSettingTab).toHaveBeenCalledTimes(1);
    expect(mocks.addCommand).toHaveBeenCalledWith(expect.objectContaining({ id: "open-conflicts" }));
    expect(mocks.vaultOn.mock.calls.map(([event]) => event)).toEqual([
      "create",
      "modify",
      "delete",
      "rename"
    ]);
    expect(mocks.statusEl.setText).toHaveBeenCalledWith("Disk: synced ✓");
    expect(mocks.requestUrl).toHaveBeenCalledTimes(2);
  });

  it("notifies and opens the modal for a newly detected manual conflict", async () => {
    mocks.requestUrl.mockImplementation(async ({ url }: { url: string }) => ({
      status: 200,
      json: url.endsWith("/conflicts")
        ? [{ id: 1, vault_id: "docs", path: "a.md", conflict_type: "Concurrent", fork_path: null }]
        : { node: "test", shares: [] }
    }));
    const plugin = new DiskArcanaPlugin({} as never, {} as never);
    await plugin.onload();

    expect(mocks.notice).toHaveBeenCalledWith("1 Disk Arcana conflict");
    expect(mocks.modalOpen).toHaveBeenCalledTimes(1);
  });
});
