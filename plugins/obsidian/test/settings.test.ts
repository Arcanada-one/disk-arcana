import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS, sanitizeSettings } from "../src/settings-model";

describe("sanitizeSettings", () => {
  it("falls back to loopback and clamps polling", () => {
    expect(sanitizeSettings({ daemonUrl: "http://example.com", pollIntervalSeconds: 1 })).toMatchObject({
      daemonUrl: DEFAULT_SETTINGS.daemonUrl,
      pollIntervalSeconds: 2
    });
    expect(sanitizeSettings({ pollIntervalSeconds: 999 }).pollIntervalSeconds).toBe(300);
    expect(sanitizeSettings({ defaultConflictAction: "invalid" as never }).defaultConflictAction).toBe(
      DEFAULT_SETTINGS.defaultConflictAction
    );
    expect(sanitizeSettings({ conflictStrategy: "invalid" as never }).conflictStrategy).toBe("manual");
    expect(sanitizeSettings({ conflictStrategy: "auto-fork" }).conflictStrategy).toBe("auto-fork");
  });
});
