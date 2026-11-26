import type { CheckId, Finding, Scan, VerificationState } from "../types";
import { CATEGORY_LABEL } from "../lib/format";

export interface FindingTemplate
  extends Omit<
    Finding,
    "id" | "scanId" | "detectedAt" | "sample" | "verification" | "rescanCount"
  > {
  verificationBefore: string;
  resolvedVerification?: {
    after: string;
    note: string;
  };
}

const requestHeaders = [
  "GET / HTTP/1.1",
  "Host: demo-app.example",
  "Accept: text/html,application/xhtml+xml",
  "User-Agent: BugHunterLab/0.1 (authorized-demo; throttled)",
];

export const FINDING_TEMPLATES: FindingTemplate[] = [
  {
    fingerprint: "path-env",
    title: "Environment file exposed at /.env",
    category: "paths",
    categoryLabel: CATEGORY_LABEL.paths,
    moduleName: "Exposed Path Detector",
    severity: "critical",
    confidence: "high",
    status: "open",
    targetPath: "/.env",
    summary:
      "A request to /.env returned HTTP 200 with a body that does not match the application's baseline 404 page. The response exposed environment variable names and redacted values.",
    impact:
      "Application secrets may allow an attacker to forge sessions, connect to the database, or move into the hosting environment. This is a direct secret-exposure path, not a theoretical misconfiguration.",
    severityRationale:
      "Rated Critical because a readable environment file can disclose signing keys and database credentials. Exposure of this class of secret commonly leads to full application compromise.",
    confidenceRationale:
      "High confidence: the response body itself contains the secret keys, and the baseline request confirms the server returns a different 404 page for paths that do not exist.",
    evidence: {
      request: [
        "GET /.env HTTP/1.1",
        "Host: demo-app.example",
        "Accept: */*",
        "User-Agent: BugHunterLab/0.1 (authorized-demo; throttled)",
      ].join("\n"),
      response: [
        "HTTP/1.1 200 OK",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Length: 214",
        "Cache-Control: no-store",
        "X-Powered-By: Werkzeug/3.0.1 Python/3.12.2",
        "",
        "APP_ENV=production",
        "APP_KEY=base64:[redacted]",
        "DB_HOST=127.0.0.1",
        "DB_PASSWORD=[redacted]",
        "SECRET_SALT=[redacted]",
      ].join("\n"),
      baseline: [
        "GET /.env-baseline-9f3c HTTP/1.1",
        "Host: demo-app.example",
        "Accept: */*",
        "",
        "HTTP/1.1 404 Not Found",
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: 2489",
        "",
        "<!doctype html>",
        "<title>Not Found</title>",
        "<h1>404 - Page not found</h1>",
      ].join("\n"),
      comparison: [
        {
          signal: "HTTP status",
          baseline: "404 Not Found",
          observed: "200 OK",
          verdict: "fail",
        },
        {
          signal: "Content-Type",
          baseline: "text/html",
          observed: "text/plain",
          verdict: "warn",
        },
        {
          signal: "Body length",
          baseline: "2,489 bytes",
          observed: "214 bytes",
          verdict: "info",
        },
        {
          signal: "Secret markers",
          baseline: "None",
          observed: "APP_KEY, DB_PASSWORD present",
          verdict: "fail",
        },
      ],
      note:
        "Secret values are redacted in this illustrative record. The scanner stores the shape of the evidence, never the live secret value.",
    },
    remediation: [
      "Remove .env from the deployed web root. Load environment variables through the process manager or secret store instead.",
      "Deny dotfiles at the reverse proxy as a defence-in-depth rule.",
      "Rotate APP_KEY, DB_PASSWORD and every other secret that was reachable. Removing the file does not undo the exposure.",
      "Add an artefact check to CI that fails the deploy if .env is present in the published directory.",
    ],
    fixSnippet: [
      "# nginx - deny hidden files before the app handles the request",
      "location ~ /\\.[^/]+ {",
      "    deny all;",
      "    return 404;",
      "}",
    ].join("\n"),
    fixLanguage: "nginx",
    references: [
      { label: "OWASP Top 10", value: "A05:2021 - Security Misconfiguration" },
      { label: "CWE", value: "CWE-538 - File and Directory Information Exposure" },
    ],
    verificationBefore: "GET /.env - 200 OK - APP_KEY and DB_PASSWORD present",
  },
  {
    fingerprint: "path-backup",
    title: "Backup directory reachable at /backup/",
    category: "paths",
    categoryLabel: CATEGORY_LABEL.paths,
    moduleName: "Exposed Path Detector",
    severity: "high",
    confidence: "medium",
    status: "pending",
    targetPath: "/backup/",
    summary:
      "A probe to /backup/ returned HTTP 200 with a directory listing containing an application archive. The response differs from the baseline 404 in status, title and body length.",
    impact:
      "A downloadable archive may contain source code, database dumps or configuration files. The contents were not downloaded during this check, so the exact sensitivity is not yet confirmed.",
    severityRationale:
      "Rated High because a publicly reachable backup is a common path to source and data disclosure. Severity may rise if the archive is confirmed to contain credentials or customer data.",
    confidenceRationale:
      "Medium confidence: the listing is directly observed, but the link between the archive and sensitive data is inferred. The archive itself was not opened. Status is Pending verification so a human can confirm the contents.",
    evidence: {
      request: [
        "GET /backup/ HTTP/1.1",
        "Host: demo-app.example",
        "Accept: text/html",
        "User-Agent: BugHunterLab/0.1 (authorized-demo; throttled)",
      ].join("\n"),
      response: [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: 1834",
        "",
        "<title>Index of /backup</title>",
        "<h1>Index of /backup</h1>",
        '<a href="backup-2026-02-17.zip">backup-2026-02-17.zip</a>   1.4M',
      ].join("\n"),
      baseline: [
        "GET /backup-baseline-7c1a/ HTTP/1.1",
        "Host: demo-app.example",
        "Accept: text/html",
        "",
        "HTTP/1.1 404 Not Found",
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: 2489",
        "",
        "<title>Not Found</title>",
      ].join("\n"),
      comparison: [
        {
          signal: "HTTP status",
          baseline: "404 Not Found",
          observed: "200 OK",
          verdict: "fail",
        },
        {
          signal: "Page title",
          baseline: "Not Found",
          observed: "Index of /backup",
          verdict: "fail",
        },
        {
          signal: "Body length",
          baseline: "2,489 bytes",
          observed: "1,834 bytes",
          verdict: "warn",
        },
        {
          signal: "Archive contents",
          baseline: "Not requested",
          observed: "Not downloaded",
          verdict: "info",
          note: "Kept out of scope. Confirm manually before raising severity.",
        },
      ],
      note:
        "HTTP 200 alone is not treated as proof. The page title, body length and baseline comparison all support that this is a real listing.",
    },
    remediation: [
      "Move backup archives outside the public web root and serve them only through an authenticated administrative interface.",
      "Block /backup/ at the reverse proxy and remove existing archives from the deployed artefact.",
      "Review the archive's contents for credentials, personal data or source code, then rotate any exposed secrets.",
      "Add a deployment check that rejects archive files inside public directories.",
    ],
    fixSnippet: [
      "# nginx - keep backup paths out of the public surface",
      "location ^~ /backup/ {",
      "    deny all;",
      "    return 404;",
      "}",
    ].join("\n"),
    fixLanguage: "nginx",
    references: [
      { label: "OWASP Top 10", value: "A01:2021 - Broken Access Control" },
      { label: "CWE", value: "CWE-552 - Files or Directories Accessible to External Parties" },
    ],
    verificationBefore: "GET /backup/ - 200 OK - directory listing returned",
  },
  {
    fingerprint: "cookie-httponly",
    title: "Session cookie missing HttpOnly",
    category: "cookies",
    categoryLabel: CATEGORY_LABEL.cookies,
    moduleName: "Cookie Security Analyzer",
    severity: "high",
    confidence: "high",
    status: "open",
    targetPath: "/login",
    summary:
      "The login response sets a session cookie without the HttpOnly attribute. Secure and SameSite=Lax are present; HttpOnly is absent from the raw Set-Cookie header.",
    impact:
      "If a cross-site scripting issue exists anywhere in the application, page scripts may be able to read the session cookie. HttpOnly does not prevent XSS, but it removes one way a stolen session can be extended.",
    severityRationale:
      "Rated High because the cookie is a session identifier. The impact depends on whether script injection is also possible, so this is a context-dependent High rather than Critical.",
    confidenceRationale:
      "High confidence: HttpOnly is directly absent from the observed Set-Cookie header. No inference or payload execution was required.",
    evidence: {
      request: [
        "POST /login HTTP/1.1",
        "Host: demo-app.example",
        "Content-Type: application/x-www-form-urlencoded",
        "",
        "username=demo&password=[redacted]",
      ].join("\n"),
      response: [
        "HTTP/1.1 302 Found",
        "Location: /account",
        "Set-Cookie: session=abc123; Secure; SameSite=Lax",
        "Content-Length: 0",
      ].join("\n"),
      checks: [
        {
          label: "Secure",
          value: "Present",
          expected: "Present",
          state: "pass",
        },
        {
          label: "HttpOnly",
          value: "Absent",
          expected: "Present",
          state: "fail",
        },
        {
          label: "SameSite",
          value: "Lax",
          expected: "Lax or Strict",
          state: "pass",
        },
      ],
      comparison: [
        {
          signal: "Set-Cookie header",
          baseline: "No baseline needed",
          observed: "session=abc123; Secure; SameSite=Lax",
          verdict: "fail",
          note: "HttpOnly is missing from the raw header.",
        },
        {
          signal: "Cookie purpose",
          baseline: "Unknown from header",
          observed: "Session identifier",
          verdict: "info",
          note: "Inferred from the login endpoint and 302 to /account.",
        },
      ],
      note:
        "The session value is a placeholder. The finding is based on the absence of a flag, not on the cookie value itself.",
    },
    remediation: [
      "Set HttpOnly on session cookies where client-side JavaScript does not need to read them.",
      "Keep Secure enabled and choose SameSite=Lax or Strict based on the login flow.",
      "Rotate the session identifier after authentication and on privilege changes.",
      "Verify the change with a rescan: the Set-Cookie header should include HttpOnly.",
    ],
    fixSnippet: [
      "response.set_cookie(",
      '    key="session",',
      "    value=session_id,",
      "    httponly=True,",
      "    secure=True,",
      '    samesite="lax",',
      "    max_age=3600,",
      ")",
    ].join("\n"),
    fixLanguage: "python",
    references: [
      { label: "OWASP Top 10", value: "A07:2021 - Identification and Authentication Failures" },
      { label: "CWE", value: "CWE-1004 - Sensitive Cookie Without HttpOnly Flag" },
    ],
    verificationBefore: "Set-Cookie: session=abc123; Secure; SameSite=Lax",
  },
  {
    fingerprint: "injection-sqli",
    title: "Potential SQL injection - database error signature",
    category: "injection",
    categoryLabel: CATEGORY_LABEL.injection,
    moduleName: "Injection Vulnerability Tester",
    severity: "critical",
    confidence: "medium",
    status: "pending",
    targetPath: "/search?q=raven'",
    summary:
      "A controlled quote probe changed the response from HTTP 200 to HTTP 500 and produced a SQLite error signature. A normal input returned results with no error. Exploitation was not attempted.",
    impact:
      "If the input reaches the query layer unsafely, an attacker may be able to alter SQL statements, read data or modify records. The database error suggests the query is constructed from input, but it does not prove exploitability.",
    severityRationale:
      "Rated Critical using the project's severity matrix: a database error signature on a probe indicates a possible data-integrity and confidentiality impact. The final severity should be re-rated if manual review shows the error came from unrelated input validation.",
    confidenceRationale:
      "Medium confidence: the status change and error text are directly observed, but the scanner did not attempt to extract data. Reflection alone is not proof. Status is Pending verification until a human confirms the query behaviour.",
    evidence: {
      request: [
        "GET /search?q=raven%27 HTTP/1.1",
        "Host: demo-app.example",
        "Accept: text/html",
        "User-Agent: BugHunterLab/0.1 (authorized-demo; throttled)",
      ].join("\n"),
      response: [
        "HTTP/1.1 500 Internal Server Error",
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: 3120",
        "",
        "Traceback (most recent call last):",
        "  ...",
        'sqlite3.OperationalError: near "\'": syntax error',
      ].join("\n"),
      baseline: [
        "GET /search?q=raven HTTP/1.1",
        "Host: demo-app.example",
        "Accept: text/html",
        "",
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: 4821",
        "",
        "3 results for \"raven\"",
      ].join("\n"),
      comparison: [
        {
          signal: "HTTP status",
          baseline: "200 OK",
          observed: "500 Internal Server Error",
          verdict: "fail",
        },
        {
          signal: "Database error text",
          baseline: "Absent",
          observed: "sqlite3.OperationalError",
          verdict: "fail",
        },
        {
          signal: "Body length",
          baseline: "4,821 bytes",
          observed: "3,120 bytes",
          verdict: "info",
        },
        {
          signal: "Reflection",
          baseline: "Query echoed in results",
          observed: "Probe not reflected",
          verdict: "info",
          note: "Reflection alone would not be treated as SQL injection.",
        },
      ],
      note:
        "The probe was a single quote, a low-impact input. No UNION, time-based or data-extraction payloads were sent.",
    },
    remediation: [
      "Build every query with parameter binding. Do not concatenate user input into SQL strings.",
      "Return a generic error page and log database exceptions server-side. Do not expose stack traces.",
      "Validate input type and length at the boundary, then test the query path with a regression probe.",
      "Review other endpoints that share the data-access layer for the same construction pattern.",
    ],
    fixSnippet: [
      "# Parameterised query - input is data, never SQL syntax",
      "cursor.execute(",
      '    "SELECT id, title FROM articles WHERE title LIKE ?",',
      '    (f"%{query}%",),',
      ")",
    ].join("\n"),
    fixLanguage: "python",
    references: [
      { label: "OWASP Top 10", value: "A03:2021 - Injection" },
      { label: "CWE", value: "CWE-89 - SQL Injection" },
    ],
    verificationBefore:
      "GET /search?q=raven' - 500 - sqlite3.OperationalError present",
  },
  {
    fingerprint: "header-csp",
    title: "Content-Security-Policy allows unsafe-inline scripts",
    category: "headers",
    categoryLabel: CATEGORY_LABEL.headers,
    moduleName: "HTTP Header Inspector",
    severity: "medium",
    confidence: "high",
    status: "open",
    targetPath: "/",
    summary:
      "A Content-Security-Policy is present, but script-src includes 'unsafe-inline' and the broad https: source. object-src and base-uri are not specified.",
    impact:
      "The policy provides weaker protection against injected scripts than a nonce- or hash-based policy. It does not create a vulnerability by itself, but it reduces the browser-side defence if an injection exists elsewhere.",
    severityRationale:
      "Rated Medium: a missing or weak CSP is a defence-in-depth weakness, not a direct exploit. The observed policy is stricter than no policy at all, which keeps it out of High.",
    confidenceRationale:
      "High confidence: the full header value is present in the response and the weak directives are directly readable.",
    evidence: {
      request: requestHeaders.join("\n"),
      response: [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline'",
        "X-Frame-Options: DENY",
        "X-Content-Type-Options: nosniff",
        "Referrer-Policy: strict-origin-when-cross-origin",
      ].join("\n"),
      checks: [
        { label: "Policy present", value: "Yes", expected: "Yes", state: "pass" },
        {
          label: "script-src",
          value: "'unsafe-inline' https:",
          expected: "nonce or hash",
          state: "fail",
        },
        {
          label: "object-src",
          value: "Not specified",
          expected: "'none'",
          state: "warn",
        },
        {
          label: "base-uri",
          value: "Not specified",
          expected: "'none' or 'self'",
          state: "warn",
        },
      ],
      comparison: [
        {
          signal: "CSP delivery",
          baseline: "Header expected",
          observed: "Present",
          verdict: "pass",
        },
        {
          signal: "Inline script",
          baseline: "Blocked",
          observed: "Allowed via unsafe-inline",
          verdict: "fail",
        },
        {
          signal: "HTTPS-only sources",
          baseline: "Explicit allowlist",
          observed: "https: wildcard",
          verdict: "warn",
        },
      ],
      note:
        "The header was read from the document response only. Subresources were not fetched.",
    },
    remediation: [
      "Replace 'unsafe-inline' with a per-request nonce or a hash allowlist for the scripts that must run.",
      "Set object-src 'none' and base-uri 'none' unless the application has a documented need.",
      "Roll the stronger policy out in Content-Security-Policy-Report-Only first and fix the violations it reports.",
      "Keep frame-ancestors in the policy as an additional clickjacking control.",
    ],
    fixSnippet: [
      "Content-Security-Policy:",
      "  default-src 'self';",
      "  script-src 'self' 'nonce-{random}' 'strict-dynamic';",
      "  object-src 'none';",
      "  base-uri 'none';",
      "  frame-ancestors 'none';",
    ].join("\n"),
    fixLanguage: "http",
    references: [
      { label: "OWASP Top 10", value: "A05:2021 - Security Misconfiguration" },
      { label: "CWE", value: "CWE-693 - Protection Mechanism Failure" },
    ],
    verificationBefore:
      "script-src 'self' 'unsafe-inline' https: - weak directives present",
  },
  {
    fingerprint: "header-hsts",
    title: "Strict-Transport-Security header missing",
    category: "headers",
    categoryLabel: CATEGORY_LABEL.headers,
    moduleName: "HTTP Header Inspector",
    severity: "medium",
    confidence: "high",
    status: "open",
    targetPath: "/",
    summary:
      "The HTTPS response did not include a Strict-Transport-Security header. Without HSTS, a browser is not told to keep future requests on HTTPS.",
    impact:
      "On a hostile network, an initial HTTP request can be intercepted before the browser upgrades. HSTS closes that downgrade window after the first successful HTTPS response.",
    severityRationale:
      "Rated Medium: the application supports HTTPS but does not instruct the browser to enforce it. This weakens transport security rather than exposing data directly.",
    confidenceRationale:
      "High confidence: the response header was directly observed as absent over an HTTPS connection.",
    evidence: {
      request: requestHeaders.join("\n"),
      response: [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: 6412",
        "Strict-Transport-Security: [absent]",
        "X-Frame-Options: DENY",
      ].join("\n"),
      checks: [
        {
          label: "HTTPS transport",
          value: "Valid certificate",
          expected: "Valid certificate",
          state: "pass",
        },
        {
          label: "HSTS header",
          value: "Absent",
          expected: "max-age >= 15552000",
          state: "fail",
        },
        {
          label: "includeSubDomains",
          value: "Not applicable",
          expected: "Only if all subdomains are HTTPS",
          state: "warn",
        },
      ],
      note:
        "No redirect from HTTP to HTTPS was tested in this check. The finding is limited to the HSTS header.",
    },
    remediation: [
      "Confirm every subdomain is HTTPS before enabling includeSubDomains.",
      "Add Strict-Transport-Security with a conservative max-age, then increase it after validation.",
      "Do not submit the domain to the HSTS preload list until the whole domain is ready for permanent HTTPS.",
    ],
    fixSnippet: [
      "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ].join("\n"),
    fixLanguage: "http",
    references: [
      { label: "OWASP Top 10", value: "A02:2021 - Cryptographic Failures" },
      { label: "CWE", value: "CWE-319 - Cleartext Transmission of Sensitive Information" },
    ],
    verificationBefore: "Strict-Transport-Security: [absent]",
  },
  {
    fingerprint: "header-xfo",
    title: "X-Frame-Options missing on the login page",
    category: "headers",
    categoryLabel: CATEGORY_LABEL.headers,
    moduleName: "HTTP Header Inspector",
    severity: "medium",
    confidence: "high",
    status: "resolved",
    targetPath: "/login",
    summary:
      "The login response did not include X-Frame-Options or a CSP frame-ancestors directive. A later rescan observed both protections present.",
    impact:
      "Without framing protection, an attacker could attempt to overlay the login page in a clickjacking attack. The risk depends on what actions the authenticated page exposes.",
    severityRationale:
      "Rated Medium: clickjacking can trick a user into an action in an authenticated session, but it requires a separate attacker-controlled page and a plausible user action.",
    confidenceRationale:
      "High confidence: the absence was directly observed, and the follow-up response now contains the exact header and CSP directive.",
    evidence: {
      request: [
        "GET /login HTTP/1.1",
        "Host: demo-app.example",
        "Accept: text/html",
        "User-Agent: BugHunterLab/0.1 (authorized-demo; throttled)",
      ].join("\n"),
      response: [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: 3912",
        "Content-Security-Policy: default-src 'self'",
        "X-Frame-Options: [absent]",
        "",
        "<!doctype html>",
        "<title>Sign in - Demo App</title>",
      ].join("\n"),
      checks: [
        {
          label: "X-Frame-Options",
          value: "Absent",
          expected: "DENY or SAMEORIGIN",
          state: "fail",
        },
        {
          label: "CSP frame-ancestors",
          value: "Not specified",
          expected: "'none' or 'self'",
          state: "fail",
        },
      ],
      note:
        "The response was captured before the fix. The verification panel shows the post-fix header.",
    },
    remediation: [
      "Set X-Frame-Options to DENY, or SAMEORIGIN if the application must frame itself.",
      "Add frame-ancestors 'none' to the Content-Security-Policy for modern browsers.",
      "Re-test the login and account pages, because framing protection may be configured per route.",
    ],
    fixSnippet: [
      "X-Frame-Options: DENY",
      "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
    ].join("\n"),
    fixLanguage: "http",
    references: [
      { label: "OWASP Top 10", value: "A05:2021 - Security Misconfiguration" },
      { label: "CWE", value: "CWE-1021 - Improper Restriction of Rendered UI Layers" },
    ],
    verificationBefore:
      "X-Frame-Options: [absent] - no frame-ancestors directive",
    resolvedVerification: {
      after: [
        "HTTP/1.1 200 OK",
        "X-Frame-Options: DENY",
        "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
      ].join("\n"),
      note:
        "Rescan observed both X-Frame-Options and frame-ancestors. The observed issue is resolved.",
    },
  },
  {
    fingerprint: "header-referrer",
    title: "Referrer-Policy header not set",
    category: "headers",
    categoryLabel: CATEGORY_LABEL.headers,
    moduleName: "HTTP Header Inspector",
    severity: "low",
    confidence: "high",
    status: "open",
    targetPath: "/account",
    summary:
      "The response did not set Referrer-Policy. The browser therefore applies its default referrer behaviour, which may send more of the URL than the application intends.",
    impact:
      "URLs can contain reset tokens, search terms or account identifiers. A permissive referrer can leak that information to third-party destinations linked from the page.",
    severityRationale:
      "Rated Low: the exposure depends on which URLs contain sensitive data and which external destinations are linked. It is a hardening gap, not an observed leak.",
    confidenceRationale:
      "High confidence: the header is absent from the direct response. The downstream impact remains contextual and is not claimed as observed.",
    evidence: {
      request: [
        "GET /account HTTP/1.1",
        "Host: demo-app.example",
        "Accept: text/html",
        "User-Agent: BugHunterLab/0.1 (authorized-demo; throttled)",
      ].join("\n"),
      response: [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        "Content-Length: 5104",
        "Referrer-Policy: [absent]",
        "Cache-Control: no-store",
      ].join("\n"),
      checks: [
        {
          label: "Referrer-Policy",
          value: "Absent",
          expected: "strict-origin-when-cross-origin",
          state: "fail",
        },
        {
          label: "Browser default",
          value: "strict-origin-when-cross-origin",
          expected: "Explicit policy preferred",
          state: "warn",
        },
      ],
      note:
        "Modern browsers use a safer default than older ones. An explicit policy makes the intent testable and consistent.",
    },
    remediation: [
      "Set Referrer-Policy: strict-origin-when-cross-origin globally.",
      "Use no-referrer on routes that handle tokens or other sensitive URL parameters.",
      "Confirm the header is applied by the proxy as well as the application.",
    ],
    fixSnippet: ["Referrer-Policy: strict-origin-when-cross-origin"].join("\n"),
    fixLanguage: "http",
    references: [
      { label: "OWASP Top 10", value: "A05:2021 - Security Misconfiguration" },
      { label: "CWE", value: "CWE-116 - Improper Encoding or Escaping of Output" },
    ],
    verificationBefore: "Referrer-Policy: [absent]",
  },
  {
    fingerprint: "header-xcto",
    title: "X-Content-Type-Options missing on static assets",
    category: "headers",
    categoryLabel: CATEGORY_LABEL.headers,
    moduleName: "HTTP Header Inspector",
    severity: "low",
    confidence: "high",
    status: "open",
    targetPath: "/static/app.js",
    summary:
      "A static JavaScript response did not include X-Content-Type-Options: nosniff. Browsers may attempt MIME sniffing when the header is absent.",
    impact:
      "MIME confusion can turn an uploaded or user-controlled file into executable content in some browser and proxy combinations. The risk is limited when content types are already correct.",
    severityRationale:
      "Rated Low: the response declares a JavaScript content type and no user-controlled upload path was observed. This is a defensive header gap.",
    confidenceRationale:
      "High confidence: the header is directly absent from the static asset response.",
    evidence: {
      request: [
        "GET /static/app.js HTTP/1.1",
        "Host: demo-app.example",
        "Accept: */*",
        "User-Agent: BugHunterLab/0.1 (authorized-demo; throttled)",
      ].join("\n"),
      response: [
        "HTTP/1.1 200 OK",
        "Content-Type: text/javascript; charset=utf-8",
        "Content-Length: 18244",
        "Cache-Control: public, max-age=3600",
        "X-Content-Type-Options: [absent]",
      ].join("\n"),
      checks: [
        {
          label: "Declared type",
          value: "text/javascript",
          expected: "text/javascript",
          state: "pass",
        },
        {
          label: "nosniff",
          value: "Absent",
          expected: "Present",
          state: "fail",
        },
      ],
      note:
        "Only the static JavaScript response was checked. Upload endpoints were not in scope.",
    },
    remediation: [
      "Add X-Content-Type-Options: nosniff to all responses at the server or proxy layer.",
      "Keep explicit Content-Type headers on every static asset.",
      "Ensure uploads and downloads have separate, controlled content-type handling.",
    ],
    fixSnippet: ["X-Content-Type-Options: nosniff"].join("\n"),
    fixLanguage: "http",
    references: [
      { label: "OWASP Top 10", value: "A05:2021 - Security Misconfiguration" },
      { label: "CWE", value: "CWE-436 - Interpretation Conflict" },
    ],
    verificationBefore: "X-Content-Type-Options: [absent]",
  },
];

export interface RescanScenario {
  outcome: "resolved" | "still-present";
  after: string;
  note: string;
}

export const RESCAN_SCENARIOS: Record<string, RescanScenario> = {
  "cookie-httponly": {
    outcome: "resolved",
    after: "Set-Cookie: session=abc123; Secure; SameSite=Lax; HttpOnly",
    note:
      "The rescan observed HttpOnly in the raw Set-Cookie header. Secure and SameSite=Lax are still present. The observed issue is resolved.",
  },
  "injection-sqli": {
    outcome: "resolved",
    after: [
      "GET /search?q=raven%27 HTTP/1.1",
      "",
      "HTTP/1.1 200 OK",
      "Content-Type: text/html; charset=utf-8",
      "",
      '3 results for "raven"',
    ].join("\n"),
    note:
      "The same controlled quote probe now returns HTTP 200 with no database error text. The observed error signature is resolved, but this does not prove the whole query layer is safe.",
  },
  "header-xfo": {
    outcome: "resolved",
    after: [
      "HTTP/1.1 200 OK",
      "X-Frame-Options: DENY",
      "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
    ].join("\n"),
    note:
      "The rescan observed both X-Frame-Options: DENY and frame-ancestors 'none'. The observed issue is resolved.",
  },
  "header-csp": {
    outcome: "still-present",
    after:
      "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline'",
    note:
      "The rescan still observed 'unsafe-inline' in script-src. The weak CSP directive remains present.",
  },
  "path-env": {
    outcome: "still-present",
    after: "HTTP/1.1 200 OK - .env still returns environment keys",
    note:
      "The rescan still receives HTTP 200 with environment variable names. The exposure remains open.",
  },
  "path-backup": {
    outcome: "still-present",
    after: "HTTP/1.1 200 OK - directory listing still reachable",
    note:
      "The rescan still observes a directory listing at /backup/. Manual confirmation of archive contents is still pending.",
  },
  "header-hsts": {
    outcome: "still-present",
    after: "Strict-Transport-Security: [absent]",
    note:
      "The rescan still observed no Strict-Transport-Security header on the HTTPS response.",
  },
  "header-referrer": {
    outcome: "still-present",
    after: "Referrer-Policy: [absent]",
    note:
      "The rescan still observed no Referrer-Policy header. The hardening gap remains open.",
  },
  "header-xcto": {
    outcome: "still-present",
    after: "X-Content-Type-Options: [absent]",
    note:
      "The rescan still observed no X-Content-Type-Options header on the static asset response.",
  },
};

export function buildFindingsForScan(scan: Scan, checks: CheckId[]): Finding[] {
  return FINDING_TEMPLATES.filter((template) => checks.includes(template.category)).map(
    (template, index) => {
      const verification: VerificationState =
        template.resolvedVerification !== undefined
          ? {
              status: "verified-resolved",
              before: template.verificationBefore,
              after: template.resolvedVerification.after,
              checkedAt: scan.startedAt,
              scanId: scan.id,
              note: template.resolvedVerification.note,
            }
          : {
              status: "not-verified",
              before: template.verificationBefore,
              note: "A rescan of this finding will re-check the observed evidence.",
            };

      return {
        ...template,
        id: `BH-${scan.sequence}${String(index + 1).padStart(2, "0")}`,
        scanId: scan.id,
        detectedAt: scan.startedAt,
        sample: true,
        verification,
        rescanCount: 0,
      };
    },
  );
}

export function applyRescanToFinding(
  finding: Finding,
  scan: Scan,
): Pick<Finding, "id" | "status" | "verification" | "rescanCount"> {
  const scenario = RESCAN_SCENARIOS[finding.fingerprint] ?? {
    outcome: "still-present" as const,
    after: "Observed evidence unchanged.",
    note: "The rescan did not observe a change in the recorded evidence.",
  };

  const resolved = scenario.outcome === "resolved";
  const status = resolved ? "resolved" : finding.status === "pending" ? "pending" : "open";

  return {
    id: finding.id,
    status,
    rescanCount: finding.rescanCount + 1,
    verification: {
      status: resolved ? "verified-resolved" : "verified-open",
      before: finding.verification.before,
      after: scenario.after,
      checkedAt: scan.completedAt ?? new Date().toISOString(),
      scanId: scan.id,
      note: scenario.note,
    },
  };
}
