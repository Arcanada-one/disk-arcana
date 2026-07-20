import { describe, expect, it, vi } from "vitest";
import { DaemonClient, normalizeLoopbackUrl } from "../src/daemon-client";

describe("normalizeLoopbackUrl", () => {
  it("accepts canonical loopback URLs", () => {
    expect(normalizeLoopbackUrl("http://127.0.0.1:9444")).toBe("http://127.0.0.1:9444");
    expect(normalizeLoopbackUrl("http://localhost:9444")).toBe("http://localhost:9444");
    expect(normalizeLoopbackUrl("http://127.0.0.2:9444")).toBe("http://127.0.0.2:9444");
  });

  it("rejects public, credentialed, and path URLs", () => {
    expect(() => normalizeLoopbackUrl("http://0.0.0.0:9444")).toThrow(/loopback/);
    expect(() => normalizeLoopbackUrl("http://127.evil.example:9444")).toThrow(/loopback/);
    expect(() => normalizeLoopbackUrl("https://127.0.0.1:9444")).toThrow(/loopback/);
    expect(() => normalizeLoopbackUrl("http://user@127.0.0.1:9444")).toThrow(/loopback/);
    expect(() => normalizeLoopbackUrl("http://127.0.0.1:9444/status")).toThrow(/path/);
  });
});

describe("DaemonClient", () => {
  it("uses share-qualified, encoded conflict paths", async () => {
    const request = vi.fn().mockResolvedValue({ status: 200, json: {} });
    const client = new DaemonClient("http://127.0.0.1:9444", request);
    await client.resolve("wiki space", "notes/a b.md", "keep-local");
    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "http://127.0.0.1:9444/conflicts/wiki%20space/notes%2Fa%20b.md",
        method: "POST",
        body: JSON.stringify({ action: "keep-local" })
      })
    );
  });

  it("surfaces non-success status without leaking response content", async () => {
    const request = vi.fn().mockResolvedValue({ status: 409, json: { secret: "not logged" } });
    const client = new DaemonClient("http://127.0.0.1:9444", request);
    await expect(client.conflicts()).rejects.toThrow("HTTP 409");
  });
});
