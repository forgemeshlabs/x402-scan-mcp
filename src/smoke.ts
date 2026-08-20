/**
 * Smoke test: scans a known-good x402 endpoint and a known-dead one, prints
 * a compact summary.
 * Run: npm run build && npm run smoke [url]
 */
import { scanEndpoint } from "./scan.js";

const target = process.argv[2] ?? "https://library.forgemesh.io/business-management";

const result = await scanEndpoint(target);
console.log(`\n=== x402 Endpoint Scan: ${result.url} ===`);
console.log(`Reachable: ${result.reachable}  HTTP: ${result.http_status}  Method: ${result.method_used}  (${result.response_time_ms}ms)`);
console.log(`402: ${result.is_402}  Envelope: ${result.x402_envelope}  Valid: ${result.envelope_valid}  MPP: ${result.mpp_dual_stack}`);
console.log(`Grade: ${result.grade}`);
if (result.accepts_summary.length) console.log(`Accepts: ${JSON.stringify(result.accepts_summary)}`);
if (result.envelope_errors.length) console.log(`Envelope errors:\n  - ${result.envelope_errors.join("\n  - ")}`);
console.log(`Findings:\n  - ${result.findings.join("\n  - ")}`);
