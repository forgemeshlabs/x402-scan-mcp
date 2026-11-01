# Changelog

## 0.1.9

- Security: the SSRF guard no longer has an environment-variable exemption. The test suite's 127.0.0.1 fixture is enabled by an internal function call only (`__setTestLoopbackExemption`), so nothing an operator sets or an MCP client sends can widen the guard.
- Security: `census_stats` reads the remote stats payload through a 64 KB bounded reader before parsing; oversized responses are reported instead of parsed.
- Dependencies: zod 3 → 4.6.7 (GHSA-mrhx-c7xc-m3w5); transitive body-parser, fast-uri, qs, ip-address and @hono/node-server advisories resolved via lockfile refresh.

## 0.1.0

- Initial release: `scan_endpoint`, `scan_batch`, and `census_stats` MCP tools.
- Free, local, no-payment health probe for x402 endpoints: validates HTTP 402 status, `PAYMENT-REQUIRED` envelope (Base64 JSON, numeric `x402Version`, non-empty `accepts[]` with required payment fields), and MPP dual-stack discovery via `WWW-Authenticate: Payment`.
- A-F grading: A (valid envelope + MPP), B (valid envelope), C (402 with missing/malformed envelope), F (not 402, unreachable, or serving paid content free).
- SSRF guard: scheme allow-list, private/reserved-IP blocking (pre- and post-DNS), port allow-list (80/443/8080/8443), no redirect following, 64KB body cap, max 2 requests per scan.
