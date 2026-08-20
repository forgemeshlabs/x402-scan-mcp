import { safeRequest, tryJson, type HttpResult } from "./http.js";
import { parseScanUrl } from "./safeurl.js";

export type EnvelopeSource = "header" | "body" | "missing";
export type Grade = "A" | "B" | "C" | "F";

export interface AcceptsSummaryItem {
  scheme?: string;
  network?: string;
  asset?: string;
  payTo?: string;
  amount?: string;
}

export interface EndpointScanResult {
  url: string;
  reachable: boolean;
  http_status: number | null;
  is_402: boolean;
  x402_envelope: EnvelopeSource;
  envelope_valid: boolean;
  envelope_errors: string[];
  accepts_summary: AcceptsSummaryItem[];
  mpp_dual_stack: boolean;
  method_used: "GET" | "POST";
  response_time_ms: number;
  grade: Grade;
  findings: string[];
}

const REQUIRED_ACCEPT_FIELDS = ["scheme", "network", "asset", "payTo", "amount"] as const;

function decodeBase64Json(value: string | undefined): Record<string, unknown> | null {
  if (!value) return null;
  try {
    const decoded = Buffer.from(value.trim(), "base64").toString("utf8");
    const parsed = JSON.parse(decoded);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function validateAccept(item: unknown, index: number, errors: string[]): AcceptsSummaryItem {
  const summary: AcceptsSummaryItem = {};
  if (!item || typeof item !== "object" || Array.isArray(item)) {
    errors.push(`accepts[${index}] is not an object`);
    return summary;
  }
  const p = item as Record<string, unknown>;
  for (const field of REQUIRED_ACCEPT_FIELDS) {
    const v = p[field];
    if (typeof v === "string" && v.length > 0) {
      summary[field] = v;
    } else {
      errors.push(`accepts[${index}] missing required field: ${field}`);
    }
  }
  return summary;
}

/**
 * Validate a decoded x402 envelope: numeric x402Version, and a non-empty
 * accepts[] where every entry carries scheme/network/asset/payTo/amount.
 */
function validateEnvelope(envelope: Record<string, unknown>): { errors: string[]; accepts: AcceptsSummaryItem[] } {
  const errors: string[] = [];
  if (typeof envelope.x402Version !== "number") {
    errors.push("x402Version is missing or not numeric");
  }
  const rawAccepts = Array.isArray(envelope.accepts) ? envelope.accepts : [];
  if (rawAccepts.length === 0) {
    errors.push("accepts[] is missing or empty");
  }
  const accepts = rawAccepts.map((item, i) => validateAccept(item, i, errors));
  return { errors, accepts };
}

function isMppDualStack(headers: Record<string, string>): boolean {
  const wwwAuth = headers["www-authenticate"];
  return typeof wwwAuth === "string" && /\bpayment\b/i.test(wwwAuth);
}

export interface BatchScanItem {
  url: string;
  result?: EndpointScanResult;
  error?: string;
}

export interface BatchScanReport {
  results: BatchScanItem[];
  summary: string;
}

const GRADE_HEALTHY: Grade[] = ["A", "B"];

/**
 * Run scanEndpoint over a list of URLs sequentially (never in parallel — this
 * keeps total outbound requests predictable and bounded). One bad URL never
 * aborts the batch; its error is captured per-item instead.
 */
export async function scanBatch(urls: string[]): Promise<BatchScanReport> {
  const results: BatchScanItem[] = [];
  for (const url of urls) {
    try {
      results.push({ url, result: await scanEndpoint(url) });
    } catch (err) {
      results.push({ url, error: err instanceof Error ? err.message : String(err) });
    }
  }

  let healthy = 0;
  let dead = 0;
  let brokenEnvelope = 0;
  for (const item of results) {
    if (!item.result) {
      dead++;
      continue;
    }
    if (GRADE_HEALTHY.includes(item.result.grade)) healthy++;
    else if (item.result.grade === "C") brokenEnvelope++;
    else dead++;
  }

  const summary = `${healthy}/${results.length} healthy, ${dead} dead, ${brokenEnvelope} broken envelope`;
  return { results, summary };
}

/**
 * Free, local, no-payment health probe for one x402 endpoint. Never sends a
 * PAYMENT-SIGNATURE and cannot spend funds — it only inspects the 402
 * challenge shape.
 */
export async function scanEndpoint(inputUrl: string): Promise<EndpointScanResult> {
  const parsed = parseScanUrl(inputUrl); // throws UnsafeUrlError before any network call
  const findings: string[] = [];
  const start = Date.now();

  let res: HttpResult = await safeRequest(parsed.toString(), { method: "GET" });
  let methodUsed: "GET" | "POST" = "GET";

  if (res.status === 405) {
    findings.push("GET returned 405 Method Not Allowed; retried once as POST with an empty JSON body to reach the payment middleware.");
    res = await safeRequest(parsed.toString(), {
      method: "POST",
      body: "{}",
      headers: { "content-type": "application/json" },
    });
    methodUsed = "POST";
  }

  const responseTimeMs = Date.now() - start;
  const reachable = res.status > 0 && !res.error;

  if (!reachable) {
    findings.push(
      `Endpoint could not be reached (${res.error ?? "no response"}) — agents will simply skip it, permanently losing that traffic.`,
    );
    return {
      url: parsed.toString(),
      reachable: false,
      http_status: null,
      is_402: false,
      x402_envelope: "missing",
      envelope_valid: false,
      envelope_errors: [],
      accepts_summary: [],
      mpp_dual_stack: false,
      method_used: methodUsed,
      response_time_ms: responseTimeMs,
      grade: "F",
      findings,
    };
  }

  const isRedirect = res.status >= 300 && res.status < 400;
  if (isRedirect) {
    const loc = res.headers["location"];
    findings.push(
      `Server returned a ${res.status} redirect${loc ? ` to ${loc}` : ""} instead of a 402 challenge on this hop — this scanner does not follow redirects, and neither will every agent's HTTP client; put the payment gate on the URL agents are actually given.`,
    );
  }

  const is402 = res.status === 402;
  const headerEnvelope = decodeBase64Json(res.headers["payment-required"]);
  const bodyParsed = tryJson(res.body);
  const bodyHasVersionField =
    (bodyParsed && typeof bodyParsed === "object" && !Array.isArray(bodyParsed) && "x402Version" in (bodyParsed as object)) ||
    res.body.includes('"x402Version"');

  let envelopeSource: EnvelopeSource = "missing";
  let envelope: Record<string, unknown> | null = null;
  const envelopeErrors: string[] = [];

  if (headerEnvelope) {
    envelopeSource = "header";
    envelope = headerEnvelope;
  } else if (bodyParsed && typeof bodyParsed === "object" && !Array.isArray(bodyParsed) && "x402Version" in (bodyParsed as object)) {
    envelopeSource = "body";
    envelope = bodyParsed as Record<string, unknown>;
  } else if (bodyHasVersionField) {
    envelopeSource = "body";
    envelopeErrors.push("Found \"x402Version\" text in the response body, but the body did not parse as a JSON envelope.");
  }

  let acceptsSummary: AcceptsSummaryItem[] = [];
  if (envelope) {
    const { errors, accepts } = validateEnvelope(envelope);
    envelopeErrors.push(...errors);
    acceptsSummary = accepts;
  }
  const envelopeValid = envelopeSource !== "missing" && envelope !== null && envelopeErrors.length === 0;

  if (!is402) {
    if (res.status >= 200 && res.status < 300) {
      findings.push(
        `Endpoint returned HTTP ${res.status} and served content directly instead of a 402 challenge — this content is being given away for free to every agent that asks, with no payment rail attached.`,
      );
    } else if (!isRedirect) {
      findings.push(
        `Endpoint returned HTTP ${res.status} instead of 402 — agents scanning for payable routes won't recognize this as an x402 endpoint at all.`,
      );
    }
  } else if (envelopeSource === "missing") {
    findings.push(
      "Got HTTP 402 but found no PAYMENT-REQUIRED header and no x402Version anywhere in the body — agents can't build a payment offer without the envelope, so they'll abandon the call even though the seller clearly intended to charge for it.",
    );
  } else if (!envelopeValid) {
    for (const err of envelopeErrors) findings.push(`Envelope problem: ${err} — agents that validate strictly will refuse to pay against a malformed offer.`);
  }

  const mppDualStack = isMppDualStack(res.headers);
  if (is402 && envelopeValid) {
    if (mppDualStack) {
      findings.push(
        "Valid x402 envelope is advertised over both the classic PAYMENT-REQUIRED header and MPP's WWW-Authenticate: Payment header — maximally discoverable across agent payment stacks.",
      );
    } else {
      findings.push(
        "Valid x402 envelope found, but no WWW-Authenticate: Payment header (MPP dual-stack) was present — agents that only discover payable routes via MPP will miss this endpoint even though the classic x402 challenge is correct.",
      );
    }
  }

  let grade: Grade;
  if (!is402) {
    grade = "F";
  } else if (!envelopeValid) {
    grade = "C";
  } else if (mppDualStack) {
    grade = "A";
  } else {
    grade = "B";
  }

  return {
    url: parsed.toString(),
    reachable: true,
    http_status: res.status,
    is_402: is402,
    x402_envelope: envelopeSource,
    envelope_valid: envelopeValid,
    envelope_errors: envelopeErrors,
    accepts_summary: acceptsSummary,
    mpp_dual_stack: mppDualStack,
    method_used: methodUsed,
    response_time_ms: responseTimeMs,
    grade,
    findings,
  };
}
