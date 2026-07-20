import type { RequestUrlParam, RequestUrlResponse } from "obsidian";
import type {
  ConflictAction,
  ConflictDiff,
  ConflictItem,
  StatusResponse
} from "./contracts";

export type RequestFn = (request: RequestUrlParam) => Promise<RequestUrlResponse>;

export function normalizeLoopbackUrl(raw: string): string {
  const url = new URL(raw);
  const loopback = isLoopbackHostname(url.hostname);
  if (url.protocol !== "http:" || !loopback || url.username || url.password) {
    throw new Error("Daemon URL must be an unauthenticated HTTP loopback address");
  }
  if (url.pathname !== "/" || url.search || url.hash) {
    throw new Error("Daemon URL must not include a path, query, or fragment");
  }
  return url.origin;
}

function isLoopbackHostname(hostname: string): boolean {
  if (hostname === "localhost" || hostname === "::1" || hostname === "[::1]") return true;
  const octets = hostname.split(".");
  return (
    octets.length === 4 &&
    octets[0] === "127" &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
  );
}

export class DaemonClient {
  private readonly baseUrl: string;

  constructor(baseUrl: string, private readonly request: RequestFn) {
    this.baseUrl = normalizeLoopbackUrl(baseUrl);
  }

  status(): Promise<StatusResponse> {
    return this.json<StatusResponse>("GET", "/status");
  }

  conflicts(): Promise<ConflictItem[]> {
    return this.json<ConflictItem[]>("GET", "/conflicts");
  }

  conflictDiff(vaultId: string, path: string): Promise<ConflictDiff> {
    return this.json<ConflictDiff>(
      "GET",
      `/conflicts/${encodeURIComponent(vaultId)}/${encodeURIComponent(path)}/diff`
    );
  }

  async resolve(vaultId: string, path: string, action: ConflictAction): Promise<void> {
    await this.json(
      "POST",
      `/conflicts/${encodeURIComponent(vaultId)}/${encodeURIComponent(path)}`,
      { action }
    );
  }

  async sync(): Promise<void> {
    await this.json("POST", "/sync");
  }

  async reloadConfig(): Promise<void> {
    await this.json("POST", "/config/reload");
  }

  private async json<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    const response = await this.request({
      url: `${this.baseUrl}${path}`,
      method,
      contentType: body === undefined ? undefined : "application/json",
      body: body === undefined ? undefined : JSON.stringify(body),
      throw: false
    });
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Disk Arcana daemon returned HTTP ${response.status}`);
    }
    return response.json as T;
  }
}
