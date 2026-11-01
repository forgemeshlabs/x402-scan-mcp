const RAIL_PULSE_URL = "https://forgemesh.io/rail-pulse.json";
const FETCH_TIMEOUT_MS = 5_000;

/**
 * Static headline numbers from the August 2026 x402 Bazaar health census.
 * Source: https://forgemesh.io/blog/x402-bazaar-health-census-august-2026
 * Kept as a fallback/context block alongside the live catalog stats below —
 * the census is a point-in-time survey, not a live feed, so it does not
 * change when rail-pulse.json updates.
 */
export const AUGUST_2026_CENSUS = {
  title: "x402 Bazaar Health Census — August 2026",
  source: "https://forgemesh.io/blog/x402-bazaar-health-census-august-2026",
  sellers_probed: 1225,
  healthy_pct: 74,
  dead_count: 206,
  serving_paid_content_free_count: 40,
  mpp_dual_stack_pct: 15,
};

export interface CensusStats {
  live_catalog: unknown | null;
  live_catalog_error?: string;
  august_2026_census: typeof AUGUST_2026_CENSUS;
}

/**
 * Best-effort fetch of the live ForgeMesh catalog stats. This is a
 * convenience call to our own public stats endpoint, not a user-supplied
 * target, so it is not routed through the SSRF guard used for scan_endpoint.
 */
/** Hard cap on the stats payload: the real response is a few KB. */
export const MAX_CENSUS_BYTES = 64 * 1024;

/** Reads at most `limit` bytes of the body; returns null (and cancels the stream) if it is larger. */
async function readBounded(res: Response, limit: number): Promise<string | null> {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) return null;
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) { await reader.cancel(); return null; }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function censusStats(): Promise<CensusStats> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(RAIL_PULSE_URL, {
      signal: controller.signal,
      headers: { "User-Agent": "forgemesh-scan-mcp/0.1", Accept: "application/json" },
    });
    if (!res.ok) {
      return { live_catalog: null, live_catalog_error: `HTTP ${res.status}`, august_2026_census: AUGUST_2026_CENSUS };
    }
    const text = await readBounded(res, MAX_CENSUS_BYTES);
    if (text === null) {
      return { live_catalog: null, live_catalog_error: `Response larger than ${MAX_CENSUS_BYTES} bytes`, august_2026_census: AUGUST_2026_CENSUS };
    }
    return { live_catalog: JSON.parse(text) as unknown, august_2026_census: AUGUST_2026_CENSUS };
  } catch (err) {
    return {
      live_catalog: null,
      live_catalog_error: err instanceof Error ? err.message : String(err),
      august_2026_census: AUGUST_2026_CENSUS,
    };
  } finally {
    clearTimeout(timer);
  }
}
