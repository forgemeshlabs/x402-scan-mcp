/**
 * scanEndpoint behavior tests against a local fixture server — run with: npm test
 * X402_SCAN_TEST_ALLOW_LOOPBACK=1 exempts exactly 127.0.0.1 from the SSRF
 * guard for the duration of these tests (see safeurl.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { scanEndpoint, scanBatch } from "./scan.js";
import { UnsafeUrlError } from "./safeurl.js";

process.env.X402_SCAN_TEST_ALLOW_LOOPBACK = "1";

function fixture(handler: (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => void): Promise<{ server: Server; base: string }> {
  const server = createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ server, base: `http://127.0.0.1:${port}` });
    });
  });
}

function validEnvelope() {
  return {
    x402Version: 1,
    accepts: [
      {
        scheme: "exact",
        network: "eip155:8453",
        asset: "0x0000000000000000000000000000000000000001",
        payTo: "0x0000000000000000000000000000000000000002",
        amount: "1000",
      },
    ],
  };
}

test("scanEndpoint grades A: valid envelope + MPP dual-stack", async (t) => {
  const { server, base } = await fixture((_req, res) => {
    const encoded = Buffer.from(JSON.stringify(validEnvelope())).toString("base64");
    res.writeHead(402, {
      "content-type": "application/json",
      "payment-required": encoded,
      "www-authenticate": 'Payment realm="x402"',
    });
    res.end("{}");
  });
  t.after(() => server.close());

  const result = await scanEndpoint(base);
  assert.equal(result.grade, "A");
  assert.equal(result.is_402, true);
  assert.equal(result.envelope_valid, true);
  assert.equal(result.mpp_dual_stack, true);
  assert.equal(result.x402_envelope, "header");
});

test("scanEndpoint grades B: valid envelope, no MPP", async (t) => {
  const { server, base } = await fixture((_req, res) => {
    const encoded = Buffer.from(JSON.stringify(validEnvelope())).toString("base64");
    res.writeHead(402, { "content-type": "application/json", "payment-required": encoded });
    res.end("{}");
  });
  t.after(() => server.close());

  const result = await scanEndpoint(base);
  assert.equal(result.grade, "B");
  assert.equal(result.mpp_dual_stack, false);
});

test("scanEndpoint grades C: 402 with missing envelope", async (t) => {
  const { server, base } = await fixture((_req, res) => {
    res.writeHead(402, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "Payment Required" }));
  });
  t.after(() => server.close());

  const result = await scanEndpoint(base);
  assert.equal(result.grade, "C");
  assert.equal(result.x402_envelope, "missing");
});

test("scanEndpoint grades C: 402 with malformed accepts[]", async (t) => {
  const { server, base } = await fixture((_req, res) => {
    const encoded = Buffer.from(JSON.stringify({ x402Version: 1, accepts: [{ scheme: "exact" }] })).toString("base64");
    res.writeHead(402, { "content-type": "application/json", "payment-required": encoded });
    res.end("{}");
  });
  t.after(() => server.close());

  const result = await scanEndpoint(base);
  assert.equal(result.grade, "C");
  assert.equal(result.envelope_valid, false);
  assert.ok(result.envelope_errors.length > 0);
});

test("scanEndpoint grades F: serves content for free (200)", async (t) => {
  const { server, base } = await fixture((_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("free content, no paywall");
  });
  t.after(() => server.close());

  const result = await scanEndpoint(base);
  assert.equal(result.grade, "F");
  assert.equal(result.is_402, false);
  assert.equal(result.reachable, true);
});

test("scanEndpoint grades F: unreachable", async () => {
  // Nothing listening on this port.
  const result = await scanEndpoint("http://127.0.0.1:1");
  assert.equal(result.grade, "F");
  assert.equal(result.reachable, false);
});

test("scanEndpoint retries as POST once on 405", async (t) => {
  const { server, base } = await fixture((req, res) => {
    if (req.method === "GET") {
      res.writeHead(405);
      res.end();
      return;
    }
    const encoded = Buffer.from(JSON.stringify(validEnvelope())).toString("base64");
    res.writeHead(402, { "content-type": "application/json", "payment-required": encoded });
    res.end("{}");
  });
  t.after(() => server.close());

  const result = await scanEndpoint(base);
  assert.equal(result.method_used, "POST");
  assert.equal(result.grade, "B");
});

test("scanEndpoint falls back to body x402Version when header is absent", async (t) => {
  const { server, base } = await fixture((_req, res) => {
    res.writeHead(402, { "content-type": "application/json" });
    res.end(JSON.stringify(validEnvelope()));
  });
  t.after(() => server.close());

  const result = await scanEndpoint(base);
  assert.equal(result.x402_envelope, "body");
  assert.equal(result.envelope_valid, true);
  assert.equal(result.grade, "B");
});

test("scanEndpoint never follows redirects", async (t) => {
  const { server, base } = await fixture((req, res) => {
    if ((req.url ?? "/") === "/") {
      res.writeHead(302, { location: "/paid" });
      res.end();
      return;
    }
    res.writeHead(200);
    res.end("should never be reached");
  });
  t.after(() => server.close());

  const result = await scanEndpoint(base);
  assert.equal(result.http_status, 302);
  assert.equal(result.grade, "F");
});

test("scanEndpoint refuses unsafe targets without any network call", async () => {
  // These are not covered by the loopback test escape hatch, so they exercise
  // the guard exactly as it behaves in production.
  await assert.rejects(() => scanEndpoint("http://10.0.0.5/x"), UnsafeUrlError);
  await assert.rejects(() => scanEndpoint("http://localhost/x"), UnsafeUrlError);
  await assert.rejects(() => scanEndpoint("http://169.254.169.254/x"), UnsafeUrlError);
});

test("scanBatch summarizes mixed results without aborting on a bad URL", async (t) => {
  const { server, base } = await fixture((_req, res) => {
    const encoded = Buffer.from(JSON.stringify(validEnvelope())).toString("base64");
    res.writeHead(402, { "content-type": "application/json", "payment-required": encoded });
    res.end("{}");
  });
  t.after(() => server.close());

  const report = await scanBatch([base, "http://127.0.0.1:1", "not a url at all!!"]);
  assert.equal(report.results.length, 3);
  assert.equal(report.results[0].result?.grade, "B");
  assert.equal(report.results[1].result?.grade, "F");
  assert.equal(report.summary, "1/3 healthy, 2 dead, 0 broken envelope");
});
