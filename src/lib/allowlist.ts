export type TargetValidationCode =
  | "empty"
  | "invalid"
  | "protocol"
  | "credentials"
  | "port"
  | "ok";

export interface TargetValidation {
  code: TargetValidationCode;
  ok: boolean;
  message: string;
  normalized?: string;
  target?: string;
  hostname?: string;
  scheme?: "http" | "https";
}

export function normalizeUrlInput(input: string): string {
  return input.trim();
}

/**
 * Lightweight frontend UX pre-check only.
 * Authoritative URL security validation, DNS resolution, and SSRF checks
 * are enforced centrally by the FastAPI backend (POST /api/targets/validate).
 */
export function validateTargetUrl(input: string): TargetValidation {
  const raw = normalizeUrlInput(input);

  if (!raw) {
    return {
      code: "empty",
      ok: false,
      message: "Enter a target URL (http:// or https://) to validate.",
    };
  }

  if (/[\s\x00-\x1f\x7f]/.test(raw) || raw.split(/[?#]/)[0].includes("\\")) {
    return {
      code: "invalid",
      ok: false,
      message: "URL contains invalid whitespace, control characters, or backslashes.",
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return {
      code: "invalid",
      ok: false,
      message: "That is not a valid URL. Include an explicit scheme, such as https://example.com.",
    };
  }

  const scheme = parsed.protocol.replace(":", "").toLowerCase();
  if (scheme !== "https" && scheme !== "http") {
    return {
      code: "protocol",
      ok: false,
      message: `Unsupported scheme "${scheme}". Only http and https targets are permitted.`,
    };
  }

  if (parsed.username || parsed.password || parsed.host === "" || raw.split("/")[2]?.includes("@")) {
    return {
      code: "credentials",
      ok: false,
      message: "Embedded credentials or '@' in the URL authority are not allowed.",
    };
  }

  if (parsed.port) {
    const portNum = Number(parsed.port);
    const defaultPort = scheme === "https" ? 443 : 80;
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535 || portNum !== defaultPort) {
      return {
        code: "port",
        ok: false,
        message: `Port ${parsed.port} is restricted by default policy (only standard port ${defaultPort} is allowed for ${scheme.toUpperCase()}).`,
      };
    }
  }

  const normalizedPath = parsed.pathname || "/";
  const normalized = `${scheme}://${parsed.hostname.toLowerCase()}${normalizedPath}${parsed.search}`;

  return {
    code: "ok",
    ok: true,
    message: "URL syntax looks valid. Submit with authorization to run backend DNS & SSRF validation.",
    normalized,
    target: normalized,
    hostname: parsed.hostname.toLowerCase(),
    scheme,
  };
}
