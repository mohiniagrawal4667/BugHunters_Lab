import assert from "node:assert/strict";
import test from "node:test";

// Ensure import.meta.env exists if needed when running outside Vite
import { validateTargetUrl } from "../src/lib/allowlist.ts";
import {
  checkBackendHealth,
  createLiveScanOnBackend,
  fetchScansFromBackend,
  validateTargetWithBackend,
} from "../src/services/api.ts";
import { buildScanReport } from "../src/lib/pdf.ts";

test("frontend precheck trims spaces and normalizes valid URLs", () => {
  const res = validateTargetUrl("   HTTPS://Example.COM/App?x=1#frag  ");
  assert.equal(res.ok, true);
  assert.equal(res.normalized, "https://example.com/App?x=1");
});

test("frontend precheck rejects empty, non-http, and embedded credentials", () => {
  assert.equal(validateTargetUrl("   ").code, "empty");
  assert.equal(validateTargetUrl("ftp://example.com").code, "protocol");
  assert.equal(validateTargetUrl("https://user:pass@example.com").code, "credentials");
  assert.equal(validateTargetUrl("https://example.com:8443").code, "port");
});

test("validateTargetWithBackend handles backend unavailable (network failure)", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new TypeError("fetch failed");
  };
  try {
    const result = await validateTargetWithBackend("https://example.com", true);
    assert.equal(result.ok, false);
    assert.equal(result.networkError, true);
    assert.match(result.error ?? "", /cannot reach/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("validateTargetWithBackend handles 502 proxy error as backend unavailable", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response("Bad Gateway", { status: 502, headers: { "content-type": "text/plain" } });
  try {
    const result = await validateTargetWithBackend("https://example.com", true);
    assert.equal(result.ok, false);
    assert.equal(result.networkError, true);
    assert.match(result.error ?? "", /unavailable/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("validateTargetWithBackend handles 200 validated and 403 rejected responses", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          valid: true,
          allowed: true,
          normalized_url: "https://example.com/",
          hostname: "example.com",
          scheme: "https",
          port: 443,
          resolved_ips: ["93.184.216.34"],
          error_code: null,
          reason: null,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );

    const okRes = await validateTargetWithBackend("https://example.com", true);
    assert.equal(okRes.ok, true);
    assert.equal(okRes.networkError, false);
    assert.equal(okRes.data?.normalized_url, "https://example.com/");

    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          valid: false,
          allowed: false,
          normalized_url: "http://127.0.0.1/",
          hostname: "127.0.0.1",
          scheme: "http",
          port: 80,
          resolved_ips: [],
          error_code: "PROHIBITED_DESTINATION",
          reason: "Loopback IP addresses (such as 127.0.0.0/8 or ::1) are prohibited.",
        }),
        { status: 403, headers: { "content-type": "application/json" } },
      );

    const rejRes = await validateTargetWithBackend("http://127.0.0.1", true);
    assert.equal(rejRes.ok, false);
    assert.equal(rejRes.networkError, false);
    assert.match(rejRes.error ?? "", /loopback/i);

    const healthOffline = await (() => {
      globalThis.fetch = async () => {
        throw new TypeError("ECONNREFUSED");
      };
      return checkBackendHealth();
    })();
    assert.equal(healthOffline.online, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("fetchScansFromBackend returns empty array for empty DB and never invents demo rows", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ scans: [], total: 0 }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  try {
    const scans = await fetchScansFromBackend();
    assert.deepEqual(scans, []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("createLiveScanOnBackend handles backend rejection cleanly", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        valid: false,
        allowed: false,
        reason: "Loopback IP addresses (such as 127.0.0.0/8 or ::1) are prohibited.",
      }),
      { status: 403, headers: { "content-type": "application/json" } },
    );
  try {
    const res = await createLiveScanOnBackend("http://127.0.0.1", ["headers"], true);
    assert.equal(res.ok, false);
    assert.match(res.error ?? "", /loopback/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("API client rejects malformed JSON or unexpected payload shape", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      new Response("{broken-json", { status: 200, headers: { "content-type": "application/json" } });
    await assert.rejects(() => fetchScansFromBackend(), /malformed json/i);

    globalThis.fetch = async () =>
      new Response(JSON.stringify({ unexpected: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    await assert.rejects(() => fetchScansFromBackend(), /missing scans array/i);

    const scanRes = await createLiveScanOnBackend("https://example.com", ["headers"], true);
    assert.equal(scanRes.ok, false);
    assert.match(scanRes.error ?? "", /rejected or malformed/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("buildScanReport generates valid multi-page PDF from live scan data", () => {
  const liveScan = {
    id: "scan-test-pdf",
    sequence: 1,
    label: "Scan 01",
    target: "https://example.com/",
    checks: ["headers", "cookies", "paths", "injection"],
    status: "completed",
    startedAt: "2026-11-26T05:00:00Z",
    completedAt: "2026-11-26T05:00:03Z",
    progress: 100,
    stages: [],
    modules: { headers: "done", cookies: "done", paths: "done", injection: "done" },
    logs: [],
    mode: "live",
    dataSource: "live",
    requestCount: 13,
    totalChecks: 4,
  };
  const liveFinding = {
    id: "scan-test-pdf-hdr-01",
    fingerprint: "header-csp-missing",
    scanId: "scan-test-pdf",
    title: "Content-Security-Policy header is missing",
    category: "headers",
    categoryLabel: "Header inspector",
    moduleName: "HTTP Header Inspector",
    severity: "medium",
    confidence: "high",
    status: "open",
    targetPath: "/",
    detectedAt: "2026-11-26T05:00:01Z",
    summary: "CSP header absent.",
    impact: "No script/frame policy.",
    severityRationale: "Rated Medium.",
    confidenceRationale: "Directly observed.",
    evidence: { request: "GET / HTTP/1.1", response: "HTTP/1.1 200 OK" },
    remediation: ["Set Content-Security-Policy."],
    references: [{ label: "CWE", value: "CWE-693" }],
    verification: { status: "not-verified", before: "Absent" },
    sample: false,
    rescanCount: 0,
  };

  const withFindings = buildScanReport(liveScan, [liveFinding]);
  assert.ok(withFindings.pageCount >= 3);
  assert.match(withFindings.filename, /^BugHunterLab_example\.com_scan-test-pdf_report\.pdf$/);
  const bytes = withFindings.doc.output("arraybuffer");
  assert.ok(bytes.byteLength > 1000);

  const emptyClean = buildScanReport(liveScan, []);
  assert.ok(emptyClean.pageCount >= 2);
});
