import type { CheckId, Finding, Scan, ScanHandlers, ScanInput, ScanRunResult } from "../types";
import { runDemoScan } from "./demoEngine";

const rawBaseUrl = (import.meta.env?.VITE_API_BASE_URL as string | undefined)?.trim();

export const API_BASE_URL = rawBaseUrl
  ? rawBaseUrl.replace(/\/+$/, "").replace(/\/api$/i, "")
  : "";
export const API_DISPLAY_URL =
  API_BASE_URL ||
  (import.meta.env?.DEV
    ? "Vite proxy (/api -> http://127.0.0.1:8000)"
    : "Same-origin API (/api)");

export function buildApiUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
}

export interface TargetValidationApiResponse {
  valid: boolean;
  allowed: boolean;
  normalized_url: string | null;
  hostname: string | null;
  scheme: "http" | "https" | null;
  port: number | null;
  resolved_ips: string[];
  error_code: string | null;
  reason: string | null;
  port_policy?: string;
}

export interface TargetValidationCallResult {
  ok: boolean;
  networkError: boolean;
  httpStatus?: number;
  data?: TargetValidationApiResponse;
  error?: string;
}

export async function validateTargetWithBackend(
  url: string,
  authorized: boolean,
  signal?: AbortSignal,
): Promise<TargetValidationCallResult> {
  try {
    const response = await fetch(buildApiUrl("/api/targets/validate"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, authorized }),
      signal,
    });

    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      return {
        ok: false,
        networkError: response.status >= 500,
        httpStatus: response.status,
        error:
          response.status >= 500
            ? "Backend validation service is unavailable (no JSON response from FastAPI server)."
            : `Unexpected response from backend (HTTP ${response.status}).`,
      };
    }

    const payload = (await response.json()) as TargetValidationApiResponse & { detail?: unknown };

    if (typeof payload.valid !== "boolean" || typeof payload.allowed !== "boolean") {
      return {
        ok: false,
        networkError: false,
        httpStatus: response.status,
        error:
          typeof payload.detail === "string"
            ? payload.detail
            : `Backend rejected the validation request (HTTP ${response.status}).`,
      };
    }

    const ok = response.ok && payload.valid && payload.allowed;
    return {
      ok,
      networkError: false,
      httpStatus: response.status,
      data: payload,
      error: ok ? undefined : (payload.reason ?? `Target rejected (HTTP ${response.status}).`),
    };
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      return {
        ok: false,
        networkError: false,
        error: "Target validation request was cancelled.",
      };
    }
    return {
      ok: false,
      networkError: true,
      error:
        "Cannot reach the FastAPI validation backend. Ensure the API server is running and reachable.",
    };
  }
}

export interface BackendHealthResult {
  online: boolean;
  phase?: number;
  database?: string;
  portPolicy?: string;
  error?: string;
}

export async function checkBackendHealth(signal?: AbortSignal): Promise<BackendHealthResult> {
  try {
    const response = await fetch(buildApiUrl("/api/health"), { signal });
    if (!response.ok) {
      return { online: false, error: `HTTP ${response.status}` };
    }
    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      return { online: false, error: "Invalid health response" };
    }
    const data = (await response.json()) as {
      status?: string;
      phase?: number;
      database?: string;
      port_policy?: string;
    };
    return {
      online: data.status === "ok",
      phase: data.phase,
      database: data.database,
      portPolicy: data.port_policy,
    };
  } catch {
    return { online: false, error: "Backend unreachable" };
  }
}

export async function fetchScansFromBackend(signal?: AbortSignal): Promise<Scan[]> {
  const response = await fetch(buildApiUrl("/api/scans"), { signal });
  if (!response.ok) {
    throw new Error(`Failed to load scans from backend (HTTP ${response.status}).`);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error("Backend scan history endpoint returned non-JSON output (is FastAPI running?).");
  }
  let payload: { scans?: unknown };
  try {
    payload = (await response.json()) as { scans?: unknown };
  } catch {
    throw new Error("Malformed JSON returned by GET /api/scans.");
  }
  if (!payload || !Array.isArray(payload.scans)) {
    throw new Error("Unexpected response shape from GET /api/scans (missing scans array).");
  }
  return payload.scans as Scan[];
}

export async function fetchFindingsFromBackend(signal?: AbortSignal): Promise<Finding[]> {
  const response = await fetch(buildApiUrl("/api/findings"), { signal });
  if (!response.ok) {
    throw new Error(`Failed to load findings from backend (HTTP ${response.status}).`);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error("Backend findings endpoint returned non-JSON output (is FastAPI running?).");
  }
  let payload: { findings?: unknown };
  try {
    payload = (await response.json()) as { findings?: unknown };
  } catch {
    throw new Error("Malformed JSON returned by GET /api/findings.");
  }
  if (!payload || !Array.isArray(payload.findings)) {
    throw new Error("Unexpected response shape from GET /api/findings (missing findings array).");
  }
  return payload.findings as Finding[];
}

export interface CreateScanCallResult {
  ok: boolean;
  scan?: Scan;
  findings?: Finding[];
  error?: string;
}

export async function createLiveScanOnBackend(
  target: string,
  checks: CheckId[],
  authorized: boolean,
  signal?: AbortSignal,
): Promise<CreateScanCallResult> {
  try {
    const response = await fetch(buildApiUrl("/api/scans"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, checks, authorized }),
      signal,
    });

    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      return {
        ok: false,
        error: "Backend scan service is unavailable (no JSON response from FastAPI server).",
      };
    }

    let payload: {
      scan?: Scan;
      findings?: Finding[];
      reason?: string;
      detail?: string;
    };
    try {
      payload = (await response.json()) as typeof payload;
    } catch {
      return {
        ok: false,
        error: `Backend returned malformed JSON (HTTP ${response.status}).`,
      };
    }

    if (!response.ok || !payload?.scan || typeof payload.scan.id !== "string") {
      return {
        ok: false,
        error: payload?.reason ?? payload?.detail ?? `Scan request rejected or malformed (HTTP ${response.status}).`,
      };
    }

    return {
      ok: true,
      scan: payload.scan,
      findings: Array.isArray(payload.findings) ? payload.findings : [],
    };
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      return { ok: false, error: "Scan request was cancelled." };
    }
    return {
      ok: false,
      error: "Cannot reach the FastAPI backend to start the scan. Ensure the API server is running and reachable.",
    };
  }
}

export interface ScannerApi {
  mode: "demo" | "live";
  run: (
    scan: Scan,
    input: ScanInput,
    handlers: ScanHandlers,
    signal: AbortSignal,
    rescanFinding?: Finding,
  ) => Promise<ScanRunResult>;
}

export const demoScannerApi: ScannerApi = {
  mode: "demo",
  async run(scan, input, handlers, signal, rescanFinding) {
    return runDemoScan(scan, input, { rescanFinding }, handlers, signal);
  },
};

export const scannerApi: ScannerApi = demoScannerApi;

export const API_CONTRACT = [
  { method: "GET", path: "/api/health", purpose: "Check FastAPI backend & SQLite database availability" },
  { method: "POST", path: "/api/targets/validate", purpose: "Validate, normalize, DNS-resolve, and authorize target URL" },
  { method: "GET", path: "/api/scans", purpose: "List persisted real scan records from SQLite" },
  { method: "POST", path: "/api/scans", purpose: "Validate target and run baseline HTTP scan persisted to SQLite" },
  { method: "GET", path: "/api/scans/{id}", purpose: "Load a single persisted scan record" },
  { method: "GET", path: "/api/scans/{id}/findings", purpose: "Load real persisted findings for a scan" },
];
