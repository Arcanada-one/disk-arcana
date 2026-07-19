import { describe, expect, it } from "vitest";
import { DaemonClient, type RequestFn } from "../src/daemon-client";

const enabled = process.env.DISK_PLUGIN_INTEGRATION === "1";

const fetchRequest: RequestFn = async (request) => {
  const response = await fetch(request.url, {
    method: request.method,
    headers: request.contentType ? { "content-type": request.contentType } : undefined,
    body: request.body
  });
  const text = await response.text();
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    text,
    json: text.length === 0 ? {} : JSON.parse(text),
    arrayBuffer: new TextEncoder().encode(text).buffer
  };
};

describe.skipIf(!enabled)("real daemon :9444", () => {
  it("reads status and resolves the persisted docs-share conflict", async () => {
    const client = new DaemonClient("http://127.0.0.1:9444", fetchRequest);
    const status = await client.status();
    expect(status.node).toBe("obsidian-integration");

    const conflicts = await client.conflicts();
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]).toMatchObject({ vault_id: "docs", path: "notes/todo.md" });

    const diff = await client.conflictDiff("docs", "notes/todo.md");
    expect(diff.local_content).toContain("local version");
    expect(diff.fork_content).toContain("remote version");

    await client.resolve("docs", "notes/todo.md", "keep-remote");
    expect(await client.conflicts()).toEqual([]);
  });
});
