import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Check,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Clock3,
  Cookie,
  Crosshair,
  FileSearch,
  Globe2,
  Info,
  LoaderCircle,
  LockKeyhole,
  Play,
  ScanLine,
  ServerOff,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import { EXAMPLE_TARGETS } from "../data/allowlist";
import { CHECK_DEFINITIONS, CHECK_ORDER } from "../data/checks";
import { normalizeUrlInput, validateTargetUrl } from "../lib/allowlist";
import { classNames, hostnameOf } from "../lib/format";
import { plannedDuration } from "../lib/scanFactory";
import {
  validateTargetWithBackend,
  type TargetValidationApiResponse,
} from "../services/api";
import type { CheckId } from "../types";
import { useWorkspace } from "../store/WorkspaceStore";
import { useToast } from "../components/ui/Toast";
import { Button } from "../components/ui/Button";
import { Panel, SectionLabel } from "../components/ui/Section";
import { CommandVisual } from "../components/visual/CinematicSplit";

const moduleIcons = {
  headers: ScanLine,
  cookies: Cookie,
  paths: FileSearch,
  injection: Terminal,
};

const shortInspect = {
  headers: "CSP / HSTS / X-Frame-Options / nosniff / Referrer-Policy",
  cookies: "Secure / HttpOnly / SameSite",
  paths: "Predefined paths / status / body / baseline comparison",
  injection: "Controlled probes / DB errors / response differences",
};

function useInitialChecks() {
  const [searchParams] = useSearchParams();
  return useMemo<CheckId[]>(() => {
    const raw = searchParams.get("checks");
    if (!raw) return [...CHECK_ORDER];
    const requested = raw
      .split(",")
      .map((value) => value.trim())
      .filter((value): value is CheckId => CHECK_ORDER.includes(value as CheckId));
    return requested.length > 0 ? requested : [...CHECK_ORDER];
  }, [searchParams]);
}

interface BackendValidationState {
  status: "idle" | "loading" | "validated" | "rejected" | "unavailable";
  forUrl: string;
  data?: TargetValidationApiResponse;
  message?: string;
}

export function NewScan() {
  const navigate = useNavigate();
  const { startLiveScan } = useWorkspace();
  const { push } = useToast();
  const initialChecks = useInitialChecks();
  const [target, setTarget] = useState("");
  const [checks, setChecks] = useState<CheckId[]>(initialChecks);
  const [consented, setConsented] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [startingScan, setStartingScan] = useState(false);
  const [backendState, setBackendState] = useState<BackendValidationState>({
    status: "idle",
    forUrl: "",
  });
  const [preparedTarget, setPreparedTarget] = useState<TargetValidationApiResponse | null>(null);

  const trimmedTarget = normalizeUrlInput(target);
  const precheck = validateTargetUrl(target);

  useEffect(() => {
    setChecks(initialChecks);
  }, [initialChecks]);

  const selectedDefinitions = CHECK_DEFINITIONS.filter((check) => checks.includes(check.id));
  const duration = plannedDuration(checks);
  const isValidating = backendState.status === "loading";
  const isBackendValidated =
    backendState.status === "validated" &&
    backendState.forUrl === trimmedTarget &&
    Boolean(backendState.data?.valid && backendState.data?.allowed);

  function handleTargetChange(nextValue: string) {
    setTarget(nextValue);
    setError(null);
    setPreparedTarget(null);
    const nextTrimmed = normalizeUrlInput(nextValue);
    if (backendState.forUrl !== nextTrimmed) {
      setBackendState({ status: "idle", forUrl: "" });
    }
  }

  function handleConsentChange(checked: boolean) {
    setConsented(checked);
    setError(null);
    setPreparedTarget(null);
    if (!checked && backendState.status === "validated") {
      setBackendState({ status: "idle", forUrl: "" });
    }
  }

  function toggleCheck(id: CheckId) {
    setError(null);
    setChecks((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  }

  function selectAll() {
    setError(null);
    setChecks([...CHECK_ORDER]);
  }

  function clearAll() {
    setError(null);
    setChecks([]);
  }

  async function runBackendValidation(requireConsentBeforeSend = false): Promise<TargetValidationApiResponse | null> {
    setError(null);
    setPreparedTarget(null);

    if (!trimmedTarget) {
      const msg = "Enter a target URL (http:// or https://) before validating.";
      setError(msg);
      setBackendState({
        status: "rejected",
        forUrl: "",
        message: msg,
      });
      return null;
    }

    if (requireConsentBeforeSend && !consented) {
      const msg = "Confirm that you own or are explicitly authorized to test this target before starting.";
      setError(msg);
      return null;
    }

    setBackendState({ status: "loading", forUrl: trimmedTarget });
    const result = await validateTargetWithBackend(trimmedTarget, consented);

    if (result.networkError) {
      const msg =
        result.error ??
        "Backend validation service is unavailable. Ensure the FastAPI server is running.";
      setBackendState({
        status: "unavailable",
        forUrl: trimmedTarget,
        message: msg,
      });
      setError(msg);
      return null;
    }

    if (!result.ok || !result.data) {
      const msg = result.error ?? result.data?.reason ?? "Target validation failed.";
      setBackendState({
        status: "rejected",
        forUrl: trimmedTarget,
        data: result.data,
        message: msg,
      });
      setError(msg);
      return null;
    }

    setBackendState({
      status: "validated",
      forUrl: trimmedTarget,
      data: result.data,
      message: "Target validated by FastAPI security gate.",
    });
    return result.data;
  }

  async function handleValidateOnly() {
    const validated = await runBackendValidation(false);
    if (validated) {
      push({
        tone: "success",
        title: "Target validated",
        description: `${validated.normalized_url ?? trimmedTarget} passed URL, DNS, and SSRF checks.`,
      });
    }
  }

  async function handleStart() {
    setError(null);
    setPreparedTarget(null);

    if (!trimmedTarget) {
      setError("Enter a target URL (http:// or https://) to begin.");
      return;
    }
    if (!consented) {
      setError("Confirm that you own or are explicitly authorized to test this target before submitting.");
      return;
    }
    if (checks.length === 0) {
      setError("Select at least one check before starting a scan.");
      return;
    }

    const validated = isBackendValidated && backendState.data
      ? backendState.data
      : await runBackendValidation(true);

    if (!validated) return;

    setStartingScan(true);
    try {
      const result = await startLiveScan({
        target: validated.normalized_url ?? trimmedTarget,
        checks,
        authorized: consented,
      });

      if (!result.ok || !result.scanId || !result.scan) {
        setError(result.error ?? "The scan could not be started on the backend.");
        return;
      }

      push({
        tone: result.scan.status === "completed" ? "success" : "info",
        title:
          result.scan.status === "completed"
            ? `${result.scan.label} persisted to database`
            : `${result.scan.label} recorded as ${result.scan.status}`,
        description:
          result.scan.status === "completed"
            ? `Baseline HTTP fetch completed for ${result.scan.target}.`
            : (result.scan.error ?? "See run log for failure details."),
      });
      navigate(`/scans/${result.scanId}/progress`);
    } finally {
      setStartingScan(false);
    }
  }

  const validationTone: "ok" | "error" | "warn" | "muted" =
    backendState.status === "unavailable" || backendState.status === "rejected"
      ? "error"
      : isBackendValidated
        ? "ok"
        : precheck.code === "empty"
          ? "muted"
          : !precheck.ok
            ? "warn"
            : "muted";

  const displayedNormalized =
    (isBackendValidated ? backendState.data?.normalized_url : null) ?? precheck.normalized ?? null;

  return (
    <div className="space-y-6">
      <section className="tactical-panel animate-fade-up overflow-hidden">
        <div className="grid lg:grid-cols-[minmax(0,0.84fr)_minmax(0,1.16fr)]">
          <CommandVisual
            image="/brand/operations-room.jpg"
            title="Target acquisition"
            caption="Dynamic target input / SSRF & DNS gate"
            kicker="Backend validated"
            imagePosition="54% 48%"
            className="h-[300px] border-b border-cyan/15 sm:h-[360px] lg:h-auto lg:min-h-[620px] lg:border-b-0 lg:border-r"
            readouts={[
              { label: "Target mode", value: "Dynamic" },
              { label: "Checks", value: "04" },
              { label: "SSRF gate", value: "Active" },
            ]}
          />

          <div className="relative overflow-hidden bg-[#060c17] p-6 sm:p-8 lg:p-9">
            <div className="command-grid absolute inset-0 opacity-[0.16]" aria-hidden="true" />
            <div className="absolute -right-24 -top-24 size-64 rounded-full bg-magenta/[0.045] blur-3xl" aria-hidden="true" />

            <div className="relative">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="mono-label text-cyan/60">Target acquisition / dynamic scope</span>
                <span
                  className={classNames(
                    "inline-flex items-center gap-1.5 rounded-[2px] border px-2 py-1 font-mono text-[8.5px] uppercase tracking-[0.12em]",
                    isBackendValidated
                      ? "border-good/30 bg-good/[0.07] text-good"
                      : backendState.status === "unavailable"
                        ? "border-critical/30 bg-critical/[0.07] text-critical"
                        : "border-cyan/25 bg-cyan/[0.05] text-cyan",
                  )}
                >
                  <span className="size-[5px] rounded-full bg-current" />
                  {isBackendValidated
                    ? "Backend validated"
                    : backendState.status === "unavailable"
                      ? "Backend offline"
                      : "FastAPI validation gate"}
                </span>
              </div>

              <h1 className="mt-5 max-w-[560px] text-balance font-display text-[34px] font-medium leading-[0.98] tracking-[-0.05em] text-paper sm:text-[44px]">
                Point the lens.
                <br />
                Validate the target.
              </h1>
              <p className="mt-3 max-w-[540px] text-pretty text-[12.5px] leading-relaxed text-lilac/50">
                Enter an authorized HTTP or HTTPS URL. The FastAPI backend trims and normalizes the
                URL, enforces standard port rules, resolves DNS, and blocks private, loopback,
                link-local, and reserved destinations before any request is allowed.
              </p>

              <div className="mt-6 flex flex-wrap items-end justify-between gap-2">
                <label htmlFor="target-url" className="font-mono text-[9px] uppercase tracking-[0.16em] text-lilac/55">
                  Target URL
                </label>
                <span className="font-mono text-[8px] uppercase tracking-[0.12em] text-lilac/25">
                  HTTP or HTTPS / standard ports / no credentials
                </span>
              </div>

              <div
                className={classNames(
                  "mt-2 flex h-14 items-center border bg-[#02060e] transition focus-within:border-cyan/55",
                  validationTone === "error"
                    ? "border-critical/45 shadow-[0_0_0_1px_rgba(255,77,109,0.08)]"
                    : validationTone === "ok"
                      ? "border-good/35 shadow-[0_0_0_1px_rgba(78,240,184,0.08)]"
                      : "border-[#22364f]",
                )}
              >
                <span className="flex h-full items-center border-r border-[#1a2b42] px-3.5">
                  <Globe2
                    className={classNames(
                      "size-4",
                      validationTone === "error"
                        ? "text-critical"
                        : validationTone === "ok"
                          ? "text-good"
                          : validationTone === "warn"
                            ? "text-gold"
                            : "text-cyan/50",
                    )}
                  />
                </span>
                <input
                  id="target-url"
                  type="url"
                  value={target}
                  onChange={(event) => handleTargetChange(event.target.value)}
                  placeholder="https://example.com"
                  spellCheck={false}
                  autoCapitalize="none"
                  autoCorrect="off"
                  className="h-full min-w-0 flex-1 bg-transparent px-3.5 font-mono text-[12.5px] text-paper outline-none placeholder:text-lilac/20"
                  aria-describedby="target-validation"
                  aria-invalid={validationTone === "error"}
                />
                {target ? (
                  <button
                    type="button"
                    aria-label="Clear target URL"
                    onClick={() => handleTargetChange("")}
                    className="mr-2 p-1.5 text-lilac/30 transition hover:bg-white/[0.04] hover:text-paper"
                  >
                    <X className="size-3.5" />
                  </button>
                ) : null}
              </div>

              <div className="mt-3 border border-[#1c2c42] bg-[#040a14] p-3.5">
                <label className="flex cursor-pointer items-start gap-2.5">
                  <input
                    id="target-authorization-checkbox"
                    type="checkbox"
                    checked={consented}
                    onChange={(event) => handleConsentChange(event.target.checked)}
                    className="peer sr-only"
                  />
                  <span
                    className={classNames(
                      "mt-0.5 flex size-[17px] shrink-0 items-center justify-center border transition peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-cyan",
                      consented
                        ? "border-cyan bg-cyan text-[#031018]"
                        : "border-[#2a3e58] bg-white/[0.03] text-transparent",
                    )}
                  >
                    <Check className="size-3" strokeWidth={3} />
                  </span>
                  <span className="text-[11px] leading-relaxed text-paper/85">
                    I confirm that I own this website or have explicit authorization to run safe
                    security checks against it.
                  </span>
                </label>

                <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-[#142338] pt-3">
                  <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-lilac/40">
                    {consented
                      ? "Authorization confirmed — ready for backend validation"
                      : "Authorization not confirmed"}
                  </span>
                  <Button
                    type="button"
                    variant="primary"
                    size="md"
                    icon={isValidating ? LoaderCircle : ShieldCheck}
                    onClick={() => void handleValidateOnly()}
                    loading={isValidating}
                    disabled={isValidating}
                  >
                    {isValidating ? "Validating..." : "Validate Target"}
                  </Button>
                </div>
              </div>

              {displayedNormalized ? (
                <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 border border-[#1a2b42] bg-[#030810] px-3 py-2">
                  <span className="font-mono text-[8px] uppercase tracking-[0.12em] text-lilac/35">
                    {isBackendValidated ? "Backend normalized URL" : "Normalized preview (unvalidated)"}
                  </span>
                  <span className="truncate font-mono text-[11px] text-cyan/85">
                    {displayedNormalized}
                  </span>
                </div>
              ) : null}

              <div
                id="target-validation"
                role="status"
                className={classNames(
                  "mt-2.5 flex items-start gap-2.5 border px-3 py-2.5",
                  validationTone === "error"
                    ? "border-critical/25 bg-critical/[0.05] text-critical"
                    : validationTone === "ok"
                      ? "border-good/25 bg-good/[0.05] text-good/95"
                      : validationTone === "warn"
                        ? "border-gold/25 bg-gold/[0.04] text-gold/90"
                        : "border-[#1c2c42] bg-white/[0.015] text-lilac/55",
                )}
              >
                {isValidating ? (
                  <LoaderCircle className="mt-0.5 size-3.5 shrink-0 animate-spin text-cyan" />
                ) : backendState.status === "unavailable" ? (
                  <ServerOff className="mt-0.5 size-3.5 shrink-0" />
                ) : validationTone === "error" ? (
                  <CircleAlert className="mt-0.5 size-3.5 shrink-0" />
                ) : validationTone === "ok" ? (
                  <ShieldCheck className="mt-0.5 size-3.5 shrink-0" />
                ) : (
                  <Info className="mt-0.5 size-3.5 shrink-0" />
                )}
                <div className="min-w-0 flex-1">
                  <p className="font-mono text-[8px] uppercase tracking-[0.14em]">
                    {isValidating
                      ? "Backend gate / validating via POST /api/targets/validate..."
                      : backendState.status === "unavailable"
                        ? "Backend gate / connection error"
                        : backendState.status === "rejected"
                          ? `Backend gate / rejected (${backendState.data?.error_code ?? "REJECTED"})`
                          : isBackendValidated
                            ? "Backend gate / validated & permitted"
                            : precheck.code === "empty"
                              ? "Backend gate / awaiting target"
                              : precheck.ok
                                ? "Local input check only — click Validate Target"
                                : "Local syntax hint — click Validate Target for backend check"}
                  </p>
                  <p className="mt-1 text-[10.5px] leading-relaxed opacity-90">
                    {isValidating
                      ? "Running backend URL normalization, DNS resolution, and SSRF IP validation..."
                      : backendState.status === "unavailable" || backendState.status === "rejected"
                        ? backendState.message
                        : isBackendValidated && backendState.data
                          ? `Validated ${backendState.data.normalized_url} (${backendState.data.scheme?.toUpperCase()} · ${backendState.data.hostname} · port ${backendState.data.port}).`
                          : precheck.ok
                            ? "URL syntax is formed, but target is NOT validated yet. Click Validate Target to check DNS, IP safety, and authorization with the backend."
                            : precheck.message}
                  </p>
                  {backendState.data && (isBackendValidated || backendState.status === "rejected") ? (
                    <div className="mt-2 grid gap-1.5 border-t border-white/10 pt-2 font-mono text-[9px] text-lilac/70 sm:grid-cols-2">
                      <div>valid: {String(backendState.data.valid)}</div>
                      <div>allowed: {String(backendState.data.allowed)}</div>
                      <div>hostname: {backendState.data.hostname ?? "—"}</div>
                      <div>scheme: {backendState.data.scheme ?? "—"}</div>
                      <div className="sm:col-span-2">
                        resolved_ips:{" "}
                        {backendState.data.resolved_ips.length > 0
                          ? backendState.data.resolved_ips.join(", ")
                          : "none disclosed"}
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>

              <div className="mt-5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="mono-label text-lilac/35">Example URL formats</p>
                  <span className="font-mono text-[8px] uppercase tracking-[0.12em] text-gold/65">
                    Format examples only · not permission to scan
                  </span>
                </div>
                <div className="mt-2.5 grid gap-2 sm:grid-cols-2">
                  {EXAMPLE_TARGETS.map((item) => {
                    const active = trimmedTarget === item.url;
                    return (
                      <button
                        key={item.origin}
                        type="button"
                        aria-pressed={active}
                        onClick={() => handleTargetChange(item.url)}
                        className={classNames(
                          "group border px-3 py-2.5 text-left transition",
                          active
                            ? "border-cyan/35 bg-cyan/[0.055]"
                            : "border-[#1c2c42] bg-white/[0.012] hover:border-cyan/25 hover:bg-cyan/[0.025]",
                        )}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate font-mono text-[10px] text-lilac/80">{item.url}</span>
                          <span
                            className={classNames(
                              "shrink-0 font-mono text-[7.5px] uppercase tracking-[0.12em]",
                              active ? "text-cyan" : "text-lilac/25",
                            )}
                          >
                            {active ? "Entered" : "Insert"}
                          </span>
                        </div>
                        <div className="mt-1 flex items-center justify-between gap-2">
                          <span className="truncate text-[9.5px] text-lilac/35">{item.label}</span>
                          <span className="shrink-0 font-mono text-[7.5px] uppercase text-lilac/25">
                            {item.environment}
                          </span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="mt-4 flex items-start gap-2.5 border border-magenta/15 bg-magenta/[0.025] px-3.5 py-3">
                <LockKeyhole className="mt-0.5 size-3.5 shrink-0 text-magenta/80" />
                <div>
                  <p className="font-mono text-[8px] uppercase tracking-[0.14em] text-magenta/85">Authorization & SSRF policy</p>
                  <p className="mt-1 text-[10px] leading-relaxed text-lilac/45">
                    Only enter websites you own or have explicit permission to assess. Localhost,
                    loopback, private networks, link-local metadata, reserved IPs, embedded
                    credentials, and unapproved ports are blocked by the backend.
                  </p>
                </div>
              </div>

              <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-[#172840] pt-3 font-mono text-[8px] uppercase tracking-[0.12em] text-lilac/30">
                <span className="flex items-center gap-1.5">
                  <Crosshair className="size-3 text-cyan/50" /> Any authorized HTTP/HTTPS target
                </span>
                <span className="flex items-center gap-1.5">
                  <ShieldCheck className="size-3 text-good/50" /> DNS + redirect re-validation
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {startingScan ? (
        <Panel className="animate-fade-up border-cyan/35 bg-cyan/[0.04] p-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <LoaderCircle className="mt-0.5 size-5 shrink-0 animate-spin text-cyan" />
              <div>
                <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-cyan">
                  Executing live backend scan
                </p>
                <h2 className="mt-1 font-display text-[18px] font-medium text-paper">
                  Scanning {backendState.data?.normalized_url ?? trimmedTarget}
                </h2>
                <p className="mt-1.5 text-[11.5px] leading-relaxed text-lilac/60">
                  Running target validation, SafeHttpClient fetch, and {checks.length} selected
                  scanner module{checks.length === 1 ? "" : "s"} on FastAPI. Waiting for real HTTP
                  observations and SQLite persistence (no simulated progress percentages).
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {selectedDefinitions.map((mod) => (
                    <span
                      key={mod.id}
                      className="inline-flex items-center gap-1.5 rounded-[2px] border border-cyan/25 bg-[#040a13] px-2 py-1 font-mono text-[9px] text-cyan/85"
                    >
                      <LoaderCircle className="size-2.5 animate-spin" />
                      {mod.name}: Running
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </Panel>
      ) : null}

      {preparedTarget ? (
        <Panel className="animate-fade-up border-good/30 bg-good/[0.03] p-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-good" />
              <div>
                <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-good">
                  Target validated & prepared
                </p>
                <h2 className="mt-1 font-display text-[18px] font-medium text-paper">
                  {preparedTarget.normalized_url}
                </h2>
                <p className="mt-1.5 text-[11.5px] leading-relaxed text-lilac/55">
                  Backend validation succeeded (hostname <span className="font-mono text-paper/80">{preparedTarget.hostname}</span>,
                  resolved IP{" "}
                  <span className="font-mono text-paper/80">
                    {preparedTarget.resolved_ips.join(", ")}
                  </span>
                  ). No fake findings or sample results are shown—live security check execution is
                  the next step (Phase 3).
                </p>
              </div>
            </div>
            <span className="rounded-[2px] border border-good/25 bg-good/[0.08] px-2.5 py-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-good">
              {checks.length} checks queued
            </span>
          </div>
        </Panel>
      ) : null}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_350px]">
        <Panel className="animate-fade-up delay-1">
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[#1a2b42] bg-[#08111e]/60 px-5 py-4">
            <div>
              <SectionLabel index="02">Security checks</SectionLabel>
              <h2 className="mt-1.5 font-display text-[18px] font-medium tracking-[-0.02em] text-paper">
                What should this run inspect?
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={selectAll}
                className="border border-cyan/20 px-2 py-1 font-mono text-[8px] uppercase tracking-[0.1em] text-cyan/70 transition hover:border-cyan/45 hover:text-cyan"
              >
                Select all
              </button>
              <button
                type="button"
                onClick={clearAll}
                className="px-2 py-1 font-mono text-[8px] uppercase tracking-[0.1em] text-lilac/35 transition hover:text-paper"
              >
                Clear
              </button>
            </div>
          </div>

          <div className="grid gap-3 p-4 md:grid-cols-2">
            {CHECK_DEFINITIONS.map((check) => {
              const Icon = moduleIcons[check.id];
              const selected = checks.includes(check.id);
              return (
                <button
                  key={check.id}
                  type="button"
                  role="checkbox"
                  aria-checked={selected}
                  onClick={() => toggleCheck(check.id)}
                  className={classNames(
                    "group relative flex min-h-[186px] flex-col border p-4 text-left transition-all",
                    selected
                      ? "border-cyan/30 bg-cyan/[0.045] shadow-[inset_0_0_40px_rgba(0,229,255,0.025)]"
                      : "border-[#1b2c44] bg-white/[0.012] hover:border-cyan/20 hover:bg-white/[0.025]",
                  )}
                >
                  <span
                    className={classNames(
                      "absolute left-0 top-4 h-7 w-px",
                      selected ? "bg-cyan shadow-[0_0_10px_rgba(0,229,255,0.7)]" : "bg-[#2a3e58]",
                    )}
                  />
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <span className={classNames("font-mono text-[8px]", selected ? "text-magenta/80" : "text-lilac/25")}>
                        M.{check.index}
                      </span>
                      <Icon className={classNames("size-4", selected ? "text-cyan" : "text-lilac/35")} strokeWidth={1.7} />
                    </div>
                    <span
                      className={classNames(
                        "flex size-[18px] items-center justify-center border transition",
                        selected
                          ? "border-cyan/60 bg-cyan/15 text-cyan"
                          : "border-[#2a3e58] text-transparent group-hover:border-cyan/30",
                      )}
                    >
                      <Check className="size-3" strokeWidth={2.5} />
                    </span>
                  </div>
                  <h3 className="mt-3 font-display text-[13.5px] font-medium tracking-[-0.01em] text-paper/90">
                    {check.name}
                  </h3>
                  <p className="mt-1.5 text-[10.5px] leading-relaxed text-lilac/45">{check.summary}</p>
                  <p className="mt-2.5 font-mono text-[8px] uppercase leading-relaxed tracking-[0.05em] text-cyan/35">
                    {shortInspect[check.id]}
                  </p>
                  <div className="mt-auto flex items-start gap-1.5 border-t border-[#1a2b42] pt-2.5">
                    <FileSearch className="mt-0.5 size-3 shrink-0 text-lilac/25" />
                    <span className="text-[9px] leading-relaxed text-lilac/30">{check.evidence}</span>
                  </div>
                </button>
              );
            })}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#172840] bg-[#030810]/50 px-4 py-3">
            <p className="flex items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.08em] text-lilac/35">
              <Info className="size-3 text-cyan/45" />
              {checks.length} of 4 checks selected / raw observations recorded first
            </p>
            <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-good/50">
              Non-destructive GET/HEAD only
            </span>
          </div>
        </Panel>

        <aside className="space-y-4 xl:sticky xl:top-[78px] xl:self-start">
          <Panel raised className="animate-fade-up delay-2">
            <div className="border-b border-[#1a2b42] bg-[#08111e]/70 px-4 py-3.5">
              <div className="flex items-center justify-between">
                <p className="mono-label text-cyan/60">Scan brief</p>
                <span className="inline-flex items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.1em] text-cyan/75">
                  <ShieldCheck className="size-3" /> Backend gate
                </span>
              </div>
              <p className="mt-2 truncate font-mono text-[11.5px] text-paper/85">
                {displayedNormalized ? hostnameOf(displayedNormalized) : "No target entered"}
              </p>
              <p className="mt-1 truncate font-mono text-[8px] uppercase tracking-[0.1em] text-lilac/35">
                {isBackendValidated
                  ? "Validated & permitted"
                  : trimmedTarget
                    ? "Pending backend validation"
                    : "Enter a URL to validate"}
              </p>
            </div>

            <div className="px-4 py-4">
              <div className="flex items-center justify-between font-mono text-[8px] uppercase tracking-[0.1em]">
                <span className="text-lilac/40">Active modules</span>
                <span className="text-paper/85">{checks.length} / 4</span>
              </div>
              <div className="mt-2.5 space-y-1.5">
                {selectedDefinitions.length === 0 ? (
                  <p className="border border-dashed border-[#2a3e58] px-3 py-3 text-[10px] text-lilac/35">
                    No checks selected. Pick at least one module to continue.
                  </p>
                ) : (
                  selectedDefinitions.map((check) => (
                    <div key={check.id} className="flex items-center gap-2 py-0.5">
                      <span className="size-[4px] rounded-full bg-good/80" />
                      <span className="text-[10.5px] text-lilac/60">{check.name}</span>
                      <Check className="ml-auto size-3 text-good/60" />
                    </div>
                  ))
                )}
              </div>

              <div className="mt-4 space-y-2 border-t border-[#172840] pt-3.5 font-mono text-[8.5px] uppercase tracking-[0.08em]">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-lilac/35">
                    <Clock3 className="size-3" /> Est. duration
                  </span>
                  <span className="text-lilac/65">~{Math.ceil(duration / 1000)}s</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-lilac/35">
                    <ShieldCheck className="size-3" /> Validation
                  </span>
                  <span
                    className={
                      isBackendValidated
                        ? "text-good"
                        : backendState.status === "unavailable" || backendState.status === "rejected"
                          ? "text-critical"
                          : "text-lilac/40"
                    }
                  >
                    {isValidating
                      ? "Checking..."
                      : isBackendValidated
                        ? "Passed"
                        : backendState.status === "unavailable"
                          ? "Offline"
                          : backendState.status === "rejected"
                            ? "Blocked"
                            : "Not run"}
                  </span>
                </div>
              </div>

              <label className="mt-4 flex cursor-pointer items-start gap-2.5">
                <input
                  type="checkbox"
                  checked={consented}
                  onChange={(event) => handleConsentChange(event.target.checked)}
                  className="peer sr-only"
                />
                <span
                  className={classNames(
                    "mt-0.5 flex size-[16px] shrink-0 items-center justify-center border transition peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-cyan",
                    consented
                      ? "border-cyan bg-cyan text-[#031018]"
                      : "border-[#2a3e58] bg-white/[0.02] text-transparent",
                  )}
                >
                  <Check className="size-2.5" strokeWidth={3} />
                </span>
                <span className="text-[10px] leading-relaxed text-lilac/55">
                  I confirm that I own this target or have explicit permission to run safe security
                  checks on it.
                </span>
              </label>
              <p className="mt-1.5 pl-6 text-[9px] leading-relaxed text-lilac/30">
                Confirmation is required before submission; it records operator intent and is not
                technical proof of authorization.
              </p>

              {error ? (
                <p className="mt-3 flex items-start gap-1.5 border border-critical/25 bg-critical/[0.06] px-2.5 py-2 text-[10px] leading-relaxed text-critical">
                  <CircleAlert className="mt-0.5 size-3 shrink-0" />
                  {error}
                </p>
              ) : null}

              <div className="mt-4 space-y-2">
                <Button
                  variant="secondary"
                  size="md"
                  icon={isValidating ? LoaderCircle : ShieldCheck}
                  className="w-full"
                  onClick={() => void handleValidateOnly()}
                  loading={isValidating}
                  disabled={isValidating}
                >
                  {isValidating ? "Validating target..." : "Validate Target"}
                </Button>

                <Button
                  variant="gold"
                  size="lg"
                  icon={startingScan ? LoaderCircle : Play}
                  className="w-full"
                  onClick={() => void handleStart()}
                  loading={isValidating || startingScan}
                  disabled={!trimmedTarget || !consented || checks.length === 0 || isValidating || startingScan}
                  title={
                    !trimmedTarget
                      ? "Enter a target URL first"
                      : !consented
                        ? "Confirm authorization before submitting"
                        : checks.length === 0
                          ? "Select at least one check"
                          : "Validate target and run baseline scan"
                  }
                >
                  {startingScan ? "Running baseline scan..." : "Start scan"}
                </Button>
              </div>
              <p className="mt-2 text-center font-mono text-[7.5px] uppercase leading-relaxed tracking-[0.1em] text-lilac/25">
                {!trimmedTarget
                  ? "Enter an HTTP or HTTPS URL."
                  : !consented
                    ? "Confirm authorization to enable submission."
                    : checks.length === 0
                      ? "Select at least one security check."
                      : "Target will be validated via POST /api/targets/validate."}
              </p>
            </div>
          </Panel>

          <Panel className="animate-fade-up delay-3">
            <div className="flex items-center gap-2 border-b border-[#1a2b42] px-4 py-3">
              <LockKeyhole className="size-3.5 text-lilac/40" />
              <p className="mono-label text-lilac/40">Scope limits</p>
            </div>
            <ul className="space-y-2 px-4 py-4">
              {[
                "HTTP and HTTPS only; standard ports by default",
                "Localhost, private, link-local, and reserved IPs blocked",
                "IP-pinned requests and validated redirects",
                "Non-destructive GET/HEAD checks only",
              ].map((item) => (
                <li key={item} className="flex items-start gap-2 text-[9.5px] leading-relaxed text-lilac/40">
                  <span className="mt-[5px] size-[3px] shrink-0 rounded-full bg-cyan/40" />
                  {item}
                </li>
              ))}
            </ul>
            <div className="flex items-center gap-1.5 border-t border-[#172840] px-4 py-2.5 font-mono text-[7.5px] uppercase tracking-[0.08em] text-lilac/25">
              <ShieldCheck className="size-3" /> RAVENX 2026 / PS-4
              <ChevronRight className="size-2.5" /> Phase 2 gate active
            </div>
          </Panel>
        </aside>
      </div>
    </div>
  );
}
