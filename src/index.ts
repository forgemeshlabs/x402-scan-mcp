#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanEndpoint, scanBatch } from "./scan.js";
import { censusStats } from "./census.js";
import { UnsafeUrlError } from "./safeurl.js";

const urlSchema = z
  .string()
  .trim()
  .min(1, "URL is required")
  .max(2048, "URL is too long")
  .describe("The x402 endpoint URL to probe, e.g. https://api.example.com/paid-route");

const server = new McpServer({
  name: "x402-scan-mcp",
  version: "0.1.3", // keep in sync with package.json and glama.json
});

function json(payload: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
}

function errorResult(err: unknown) {
  const blocked = err instanceof UnsafeUrlError;
  const msg = err instanceof Error ? err.message : String(err);
  return {
    content: [{ type: "text" as const, text: `${blocked ? "Refused (unsafe target): " : "Error: "}${msg}` }],
    isError: true,
  };
}

server.registerTool(
  "scan_endpoint",
  {
    title: "Scan one x402 endpoint for a well-formed 402 challenge",
    description:
      "Free, local, no-payment health probe for one x402 endpoint. GETs the URL (retries once as POST with {} on a 405), then checks: is the response HTTP 402; does it carry a valid PAYMENT-REQUIRED envelope (Base64 JSON with numeric x402Version and a non-empty accepts[] where every entry has scheme/network/asset/payTo/amount), falling back to checking the body for an x402Version field; and does it also advertise MPP dual-stack via WWW-Authenticate: Payment. " +
      "Grades A (valid envelope + MPP dual-stack), B (valid envelope only), C (402 but the envelope is missing or malformed), or F (not 402, unreachable, or serving paid content for free). " +
      "Never sends a PAYMENT-SIGNATURE and cannot spend funds — this only inspects the challenge shape. Refuses non-http(s) URLs, localhost/.internal/.local hosts, private/reserved IPs, and ports outside 80/443/8080/8443; never follows redirects; caps the response body at 64KB; makes at most 2 requests.",
    inputSchema: { url: urlSchema },
  },
  async ({ url }) => {
    try {
      return json(await scanEndpoint(url));
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "scan_batch",
  {
    title: "Scan up to 10 x402 endpoints at once",
    description:
      "Runs scan_endpoint sequentially over a list of URLs (max 10) and returns each full result plus a one-line summary, e.g. '7/10 healthy, 2 dead, 1 broken envelope'. One bad URL never aborts the batch — its error is reported per-item instead. Same no-spend, SSRF-guarded probe as scan_endpoint applied to every URL.",
    inputSchema: {
      urls: z.array(urlSchema).min(1, "Provide at least one URL").max(10, "scan_batch accepts at most 10 URLs at a time"),
    },
  },
  async ({ urls }) => json(await scanBatch(urls)),
);

server.registerTool(
  "census_stats",
  {
    title: "x402 Bazaar health census stats",
    description:
      "Fetches the latest ForgeMesh catalog stats (best-effort, 5s timeout, no input required) alongside the static headline numbers from the August 2026 x402 Bazaar health census: 1,225 sellers probed, 74% healthy, 206 dead, 40 serving paid content for free, and 15% MPP dual-stack. Source: https://forgemesh.io/blog/x402-bazaar-health-census-august-2026",
    inputSchema: {},
  },
  async () => json(await censusStats()),
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("x402-scan-mcp: x402 Endpoint Scanner running on stdio");
