/**
 * Focused security tests — run with: npm test
 * Uses the built-in node:test runner (Node 18+), no extra deps.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseScanUrl, isBlockedIp, assertResolvableAndPublic, UnsafeUrlError, MAX_URL_LENGTH } from "./safeurl.js";

test("parseScanUrl adds https:// to bare hosts", () => {
  assert.equal(parseScanUrl("example.com").protocol, "https:");
  assert.equal(parseScanUrl("example.com").hostname, "example.com");
});

test("parseScanUrl rejects non-http schemes", () => {
  for (const bad of ["file:///etc/passwd", "ftp://example.com", "gopher://x", "data:text/plain,hi"]) {
    assert.throws(() => parseScanUrl(bad), UnsafeUrlError, bad);
  }
});

test("parseScanUrl rejects embedded credentials", () => {
  assert.throws(() => parseScanUrl("https://user:pass@example.com"), UnsafeUrlError);
});

test("parseScanUrl rejects overlong input", () => {
  assert.throws(() => parseScanUrl("https://example.com/" + "a".repeat(MAX_URL_LENGTH)), UnsafeUrlError);
});

test("parseScanUrl strips fragments", () => {
  assert.equal(parseScanUrl("https://example.com/x#secret").hash, "");
});

test("parseScanUrl allows the standard and alternate HTTP(S) ports", () => {
  for (const url of ["https://example.com", "http://example.com", "https://example.com:8443/x", "http://example.com:8080/x"]) {
    assert.doesNotThrow(() => parseScanUrl(url), url);
  }
});

test("parseScanUrl rejects ports outside the allow-list", () => {
  for (const url of ["https://example.com:22", "http://example.com:3000", "https://example.com:9443"]) {
    assert.throws(() => parseScanUrl(url), UnsafeUrlError, url);
  }
});

test("parseScanUrl rejects localhost-family names without any DNS lookup", () => {
  for (const h of ["http://localhost", "http://foo.local", "http://svc.internal"]) {
    assert.throws(() => parseScanUrl(h), UnsafeUrlError, h);
  }
});

test("isBlockedIp blocks loopback, private, link-local, CGNAT, metadata", () => {
  for (const ip of [
    "127.0.0.1", "127.1.2.3", "0.0.0.0", "10.0.0.1", "172.16.0.1", "172.31.255.255",
    "192.168.1.1", "169.254.169.254", "100.64.0.1", "224.0.0.1", "255.255.255.255",
    "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:127.0.0.1",
  ]) {
    assert.equal(isBlockedIp(ip), true, `expected blocked: ${ip}`);
  }
});

test("isBlockedIp allows public addresses", () => {
  for (const ip of ["8.8.8.8", "1.1.1.1", "104.16.0.1", "172.15.0.1", "172.32.0.1", "2606:4700:4700::1111"]) {
    assert.equal(isBlockedIp(ip), false, `expected allowed: ${ip}`);
  }
});

test("isBlockedIp refuses non-IP strings", () => {
  assert.equal(isBlockedIp("not-an-ip"), true);
  assert.equal(isBlockedIp(""), true);
});

test("assertResolvableAndPublic rejects literal private IP hosts without DNS", async () => {
  await assert.rejects(() => assertResolvableAndPublic(parseScanUrl("http://127.0.0.1")), UnsafeUrlError);
  await assert.rejects(() => assertResolvableAndPublic(parseScanUrl("http://169.254.169.254")), UnsafeUrlError);
  await assert.rejects(() => assertResolvableAndPublic(parseScanUrl("http://[::1]")), UnsafeUrlError);
});
