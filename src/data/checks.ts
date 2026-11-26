import type { CheckDefinition } from "../types";

export const CHECK_DEFINITIONS: CheckDefinition[] = [
  {
    id: "headers",
    index: "01",
    name: "HTTP Header Inspector",
    shortName: "Headers",
    summary:
      "Inspects the response headers that let a browser enforce security boundaries.",
    inspects: [
      "Content-Security-Policy",
      "Strict-Transport-Security",
      "X-Frame-Options",
      "X-Content-Type-Options",
      "Referrer-Policy",
    ],
    evidence: "Raw response headers, with the observed value and the recommended value side by side.",
  },
  {
    id: "cookies",
    index: "02",
    name: "Cookie Security Analyzer",
    shortName: "Cookies",
    summary:
      "Parses every Set-Cookie header and checks the flags that protect a session.",
    inspects: ["Secure", "HttpOnly", "SameSite"],
    evidence: "The exact Set-Cookie header, with each attribute parsed as present, absent or weak.",
  },
  {
    id: "paths",
    index: "03",
    name: "Exposed Path Detector",
    shortName: "Exposed paths",
    summary:
      "Compares known sensitive paths against a baseline request to a path that does not exist.",
    inspects: ["Predefined sensitive paths", "Status code", "Response body and title", "Baseline comparison"],
    evidence:
      "Status, content type and body length for both the probe and the baseline - never status 200 alone.",
  },
  {
    id: "injection",
    index: "04",
    name: "Injection Vulnerability Tester",
    shortName: "Injection",
    summary:
      "Sends a controlled, low-impact probe and compares it with a normal baseline input.",
    inspects: ["Database error signatures", "Status and length changes", "Reflection behaviour"],
    evidence:
      "Baseline response versus probe response. Reflection alone is reported as a weak signal, not proof.",
  },
];

export const CHECK_BY_ID = Object.fromEntries(
  CHECK_DEFINITIONS.map((check) => [check.id, check]),
) as Record<CheckDefinition["id"], CheckDefinition>;

export const CHECK_ORDER = CHECK_DEFINITIONS.map((check) => check.id);
