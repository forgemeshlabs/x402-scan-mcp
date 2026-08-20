import { request as nodeHttpRequest, type IncomingMessage } from "node:http";
import { request as nodeHttpsRequest } from "node:https";
import type { LookupFunction } from "node:net";
import { gunzipSync, inflateSync, brotliDecompressSync } from "node:zlib";
import { assertResolvableAndPublic, parseScanUrl, type ResolvedSafeUrl } from "./safeurl.js";

export const USER_AGENT = "forgemesh-scan-mcp/0.1";
export const TIMEOUT_MS = 8_000;
export const MAX_BODY = 64 * 1024;

export interface HttpResult {
  ok: boolean;
  status: number;
  headers: Record<string, string>;
  body: string;
  contentType: string;
  error?: string;
}

/**
 * GET/POST a single hop, dialing the exact IP that assertResolvableAndPublic
 * validated instead of re-resolving DNS at connect time. This closes the
 * validate-then-fetch DNS-rebinding window. TLS still verifies the
 * certificate against the original hostname. Redirects are never followed —
 * the caller sees the raw 3xx status and Location header, if any.
 */
function pinnedRequest(
  url: URL,
  pin: ResolvedSafeUrl,
  options: { method: string; body?: string; headers?: Record<string, string> },
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  const lookup: LookupFunction = (_host, opts, cb) => {
    if (opts.all) {
      (cb as unknown as (err: null, addrs: { address: string; family: number }[]) => void)(null, [
        { address: pin.ip, family: pin.family },
      ]);
    } else {
      (cb as unknown as (err: null, address: string, family: number) => void)(null, pin.ip, pin.family);
    }
  };

  return new Promise((resolve, reject) => {
    const requestFn = url.protocol === "https:" ? nodeHttpsRequest : nodeHttpRequest;
    const req = requestFn(
      url,
      {
        method: options.method,
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "application/json, */*",
          "Accept-Encoding": "identity",
          ...options.headers,
        },
        lookup,
      },
      (res: IncomingMessage) => {
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (v !== undefined) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          chunks.push(chunk);
          size += chunk.length;
          if (size >= MAX_BODY) res.destroy(); // cap the download, keep what we have
        });
        const settle = () => {
          clearTimeout(deadline);
          const raw = Buffer.concat(chunks);
          resolve({ status: res.statusCode ?? 0, headers, body: decodeBody(raw, headers) });
        };
        res.on("end", settle);
        res.on("close", settle);
        res.on("error", settle);
      },
    );
    const deadline = setTimeout(() => req.destroy(new Error(`Request timed out after ${TIMEOUT_MS}ms`)), TIMEOUT_MS);
    req.on("error", (err) => {
      clearTimeout(deadline);
      reject(err);
    });
    req.end(options.body);
  });
}

/**
 * We ask for identity encoding, but some servers compress anyway; decompress
 * with a hard output cap so a compression bomb cannot expand past MAX_BODY.
 */
function decodeBody(raw: Buffer, headers: Record<string, string>): string {
  const encoding = (headers["content-encoding"] ?? "").toLowerCase();
  let buf = raw;
  try {
    if (encoding.includes("gzip")) buf = gunzipSync(raw, { maxOutputLength: MAX_BODY });
    else if (encoding.includes("br")) buf = brotliDecompressSync(raw, { maxOutputLength: MAX_BODY });
    else if (encoding.includes("deflate")) buf = inflateSync(raw, { maxOutputLength: MAX_BODY });
  } catch {
    return "";
  }
  const text = buf.toString("utf8");
  return text.length > MAX_BODY ? text.slice(0, MAX_BODY) : text;
}

/**
 * SSRF-safe single-hop request. Validates the URL and scheme/port
 * allow-list, resolves DNS and rejects private/reserved targets, then dials
 * the pinned IP. Never follows redirects — a 3xx comes back as-is with its
 * Location header intact for the caller to report, not chase.
 */
export async function safeRequest(
  url: string,
  opts: { method?: string; body?: string; headers?: Record<string, string> } = {},
): Promise<HttpResult> {
  const parsed = parseScanUrl(url); // throws UnsafeUrlError — no network call made
  const pin = await assertResolvableAndPublic(parsed); // throws UnsafeUrlError — no network call made

  try {
    const res = await pinnedRequest(parsed, pin, {
      method: (opts.method ?? "GET").toUpperCase(),
      body: opts.body,
      headers: opts.headers,
    });
    return {
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      headers: res.headers,
      body: res.body,
      contentType: (res.headers["content-type"] ?? "").toLowerCase(),
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      headers: {},
      body: "",
      contentType: "",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export function tryJson(body: string): unknown | null {
  const trimmed = body.trim();
  if (!trimmed || (!trimmed.startsWith("{") && !trimmed.startsWith("["))) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}
