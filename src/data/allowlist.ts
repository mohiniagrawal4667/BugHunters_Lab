import type { AuthorizedTarget } from "../types";

/**
 * URL format examples only (for quick input testing in New Investigation).
 * Entering or selecting an example does NOT grant permission to scan it.
 */
export const EXAMPLE_TARGETS: AuthorizedTarget[] = [
  {
    url: "https://example.com",
    origin: "https://example.com",
    label: "HTTPS format example",
    environment: "Public example",
    note: "Format demonstration only. Explicit authorization is required before scanning.",
  },
  {
    url: "https://owasp.org",
    origin: "https://owasp.org",
    label: "HTTPS domain example",
    environment: "Public example",
    note: "Format demonstration only. Explicit authorization is required before scanning.",
  },
];

// Kept for backward compatibility if referenced elsewhere.
export const AUTHORIZED_TARGETS = EXAMPLE_TARGETS;
