import { afterEach, describe, expect, it, vi } from "vitest";
import { SyncDebounce } from "../src/sync-debounce";

afterEach(() => vi.useRealTimers());

describe("SyncDebounce", () => {
  it("coalesces bursts and can cancel pending sync", () => {
    vi.useFakeTimers();
    const callback = vi.fn();
    const debounce = new SyncDebounce(500, callback);
    debounce.queue();
    debounce.queue();
    vi.advanceTimersByTime(499);
    expect(callback).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(callback).toHaveBeenCalledTimes(1);

    debounce.queue();
    debounce.cancel();
    vi.runAllTimers();
    expect(callback).toHaveBeenCalledTimes(1);
  });
});
