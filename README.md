# x402-scan-mcp — the free x402 Endpoint Scanner

**Is your paid endpoint actually payable by agents?**

Shipping a `402 Payment Required` response is not the same as shipping a *correct* one. A missing field in `accepts[]`, a malformed Base64 envelope, or content that leaks for free when the payment gate is misconfigured all look fine in a browser and invisibly cost you every agent that would have paid.

`x402-scan-mcp` is the free, open-source **x402 Endpoint Scanner** — an [MCP](https://modelcontextprotocol.io) server that probes one or more x402 endpoints and reports whether an agent can actually discover, parse, and pay for them. The npm package is `@forgemeshlabs/x402-scan-mcp`.

> No payment is ever sent. The scanner never supplies a `PAYMENT-SIGNATURE`, so it cannot authorize or settle a transaction — it only inspects the shape of the 402 challenge.

```
=== x402 Endpoint Scan: https://library.forgemesh.io/business-management ===
Reachable: true  HTTP: 402  Method: GET  (184ms)
402: true  Envelope: header  Valid: true  MPP: true
Grade: A
Findings:
  - Valid x402 envelope is advertised over both the classic PAYMENT-REQUIRED header
    and MPP's WWW-Authenticate: Payment header — maximally discoverable across agent
    payment stacks.
```

## What it checks

- **HTTP 402 status** — does the route actually return `402 Payment Required`, or does it 200/404/500 and go unnoticed by payment-aware agents?
- **`PAYMENT-REQUIRED` envelope** — is the header present, Base64-decodable, valid JSON, with a numeric `x402Version` and a non-empty `accepts[]`? Falls back to checking the response body for an `x402Version` field on endpoints that put the envelope there instead.
- **Required payment fields** — does every entry in `accepts[]` carry `scheme`, `network`, `asset`, `payTo`, and `amount`?
- **MPP dual-stack** — is the endpoint also discoverable via the `WWW-Authenticate: Payment` header, the [MPP](https://github.com/x402-foundation/x402) discovery path some agent stacks use instead of the classic header?
- **Free-content leaks** — does the route serve real content with a `200` when it should be gated behind `402`?

Every result is graded **A** (valid envelope + MPP dual-stack), **B** (valid envelope, classic header only), **C** (`402` but the envelope is missing or malformed), or **F** (not `402`, unreachable, or serving paid content for free) — plus plain-English `findings[]` explaining what an agent sees and why it costs you traffic.

## Install

Requires Node.js ≥ 20. Published on npm as [`@forgemeshlabs/x402-scan-mcp`](https://www.npmjs.com/package/@forgemeshlabs/x402-scan-mcp) — no clone or build needed.

```bash
npm install -g @forgemeshlabs/x402-scan-mcp
```

Or skip the install entirely and run it with `npx` (recommended for MCP clients):

```bash
npx -y @forgemeshlabs/x402-scan-mcp
```

### Claude Code

```bash
claude mcp add x402-scan -- npx -y @forgemeshlabs/x402-scan-mcp
```

### Claude Desktop / Cursor / Windsurf (any MCP client)

```json
{
  "mcpServers": {
    "x402-scan": {
      "command": "npx",
      "args": ["-y", "@forgemeshlabs/x402-scan-mcp"]
    }
  }
}
```

### Development (from source)

Only needed if you're hacking on the scanner itself:

```bash
git clone https://github.com/forgemeshlabs/x402-scan-mcp
cd x402-scan-mcp
npm install && npm run build
claude mcp add x402-scan -- node /path/to/x402-scan-mcp/dist/index.js
```

## Tools

| Tool | What it does |
|---|---|
| `scan_endpoint` | Probe one x402 endpoint — HTTP status, envelope source/validity, `accepts[]` summary, MPP dual-stack, A-F grade, findings |
| `scan_batch` | Run `scan_endpoint` over up to 10 URLs, sequentially, plus a one-line summary like `7/10 healthy, 2 dead, 1 broken envelope` |
| `census_stats` | Live ForgeMesh catalog stats plus the static August 2026 x402 Bazaar health census headline numbers |

Try it: *"Scan my x402 route for a valid 402 challenge"* · *"Batch-scan these 5 endpoints and tell me which ones are broken"* · *"What did the August 2026 x402 health census find?"*

### CLI smoke test (from a source checkout)

```bash
npm run smoke -- https://your-endpoint.example.com
```

## Beyond the free local scan

This MCP server is local-only and free: it never leaves your machine except to call the endpoint you point it at (and, for `census_stats`, ForgeMesh's own public stats endpoint). If you want more:

- **Hosted, paid, server-side scan** — `POST https://x402.forgemesh.io/x402-endpoint-scan`, $0.05 via [x402](https://x402.org). Useful when you want the probe to originate from a different network than yours, or you're calling it from an agent that already pays x402 for other tools.
- **Browser tool** — [forgemesh.io/scan](https://forgemesh.io/scan) for a one-off scan with no MCP client or wallet needed.
- **$5 full report with fixes** — a deeper audit with ready-to-paste fixes for every failing check, at [forgemesh.io/scan](https://forgemesh.io/scan).

## The August 2026 x402 Bazaar health census

`census_stats` bundles the headline numbers from ForgeMesh's own sweep of the x402 Bazaar catalog: **1,225 sellers probed, 74% healthy, 206 dead, 40 serving paid content for free, and only 15% MPP dual-stack.** Full writeup: [forgemesh.io/blog/x402-bazaar-health-census-august-2026](https://forgemesh.io/blog/x402-bazaar-health-census-august-2026).

## Security

This scanner makes outbound requests to URLs you give it, so it is built to resist SSRF abuse:

- **Scheme allow-list** — only `http`/`https`; `file:`, `ftp:`, `gopher:`, `data:` etc. are rejected.
- **Port allow-list** — only `80`, `443`, `8080`, and `8443`. Any other explicit port is refused before any DNS lookup or network call.
- **Local-hostname rejection** — `localhost`, `*.localhost`, `*.local`, and `*.internal` are refused by name, before DNS resolution runs.
- **Private-target blocking** — after DNS resolution, requests to loopback, private (RFC 1918), link-local, CGNAT, reserved, multicast, and the cloud metadata address (`169.254.169.254`) are refused. IPv6 loopback/ULA/link-local and IPv4-mapped forms are covered too. If a hostname resolves to *any* private address, the scan is refused.
- **Pinned-IP transport** — the request dials the exact public IP that was validated, while TLS still verifies the original hostname. This closes the validate-then-connect DNS rebinding window.
- **No redirect following** — a `3xx` response is reported as-is (status + `Location`, if any); the scanner never chases it. This matches how a strict agent client behaves and keeps the request count predictable.
- **Bounded** — at most 2 requests per `scan_endpoint` call (one GET, plus one POST retry only on `405`), `forgemesh-scan-mcp/0.1` UA, 8s timeout, 64KB body cap.
- **Tested hardening** — `npm test` covers unsafe URL rejection, private IP ranges, port allow-listing, and endpoint-scan grading against a local fixture server.

**Deployment:** `stdio` (local, per-user) is the safe default. A public **HTTP** deployment is a network-egress tool and **must** add authentication, per-client rate limiting, request logging, and an egress policy before exposure.

## License

MIT — free for everyone. If the scanner found a broken 402, the fix is usually a one-line envelope correction.
