# Changelog

## 0.1.0

- Initial release: `scan_endpoint`, `scan_batch`, and `census_stats` MCP tools.
- Free, local, no-payment health probe for x402 endpoints: validates HTTP 402 status, `PAYMENT-REQUIRED` envelope (Base64 JSON, numeric `x402Version`, non-empty `accepts[]` with required payment fields), and MPP dual-stack discovery via `WWW-Authenticate: Payment`.
- A-F grading: A (valid envelope + MPP), B (valid envelope), C (402 with missing/malformed envelope), F (not 402, unreachable, or serving paid content free).
- SSRF guard: scheme allow-list, private/reserved-IP blocking (pre- and post-DNS), port allow-list (80/443/8080/8443), no redirect following, 64KB body cap, max 2 requests per scan.
