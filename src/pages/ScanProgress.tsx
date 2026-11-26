import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Circle,
  CircleAlert,
  Clock3,
  Cookie,
  FileSearch,
  FileText,
  Globe2,
  Info,
  LoaderCircle,
  LockKeyhole,
  Play,
  RefreshCw,
  ScanLine,
  ShieldCheck,
  Terminal,
  XCircle,
} from "lucide-react";
import { useWorkspace } from "../store/WorkspaceStore";
import { Button, ButtonLink } from "../components/ui/Button";
import { ConfidenceMeter, DemoBadge, SeverityBadge, StatusBadge } from "../components/ui/Badges";
import { CodeBlock } from "../components/ui/CodeBlock";
import { Panel, SectionLabel } from "../components/ui/Section";
import {
  SeverityLegend,
  SeverityStrip,
  countSeverities,
} from "../components/ui/SeverityDistribution";
import { CHECK_ORDER } from "../data/checks";
import {
  classNames,
  confidenceRank,
  formatDateTime,
  formatDuration,
  formatRelative,
  hostnameOf,
  pluralize,
  severityRank,
} from "../lib/format";
import type { CheckId, CheckResultRecord, CheckStatus, Finding, ModuleState, ScanStage } from "../types";

const moduleIcons = {
  headers: ScanLine,
  cookies: Cookie,
  paths: FileSearch,
  injection: Terminal,
};

const moduleNames: Record<CheckId, string> = {
  headers: "HTTP Header Inspector",
  cookies: "Cookie Security Analyzer",
  paths: "Exposed Path Inspector",
  injection: "Injection Inspector",
};

const checkStatusBadge: Record<CheckStatus, { label: string; className: string }> = {
  finding_detected: { label: "Finding detected", className: "border-gold/30 bg-gold/[0.08] text-gold" },
  no_issue_observed: { label: "No issue observed", className: "border-good/30 bg-good/[0.08] text-good" },
  inconclusive: { label: "Inconclusive", className: "border-medium/30 bg-medium/[0.08] text-medium" },
  not_applicable: { label: "Not applicable", className: "border-lilac/20 bg-white/[0.04] text-lilac/65" },
  scan_failed: { label: "Scan failed", className: "border-critical/35 bg-critical/[0.09] text-critical" },
};

const fallbackModuleBadge: Record<ModuleState, { label: string; className: string }> = {
  idle: { label: "Pending", className: "border-lilac/15 bg-white/[0.02] text-lilac/40" },
  queued: { label: "Pending", className: "border-lilac/15 bg-white/[0.02] text-lilac/45" },
  running: { label: "Running", className: "border-cyan/30 bg-cyan/[0.08] text-cyan" },
  done: { label: "Completed", className: "border-good/25 bg-good/[0.06] text-good" },
  skipped: { label: "Skipped", className: "border-lilac/10 bg-white/[0.01] text-lilac/30" },
  failed: { label: "Failed", className: "border-critical/30 bg-critical/[0.08] text-critical" },
};

const scanStatusStyle = {
  running: { label: "Running", className: "border-cyan/30 bg-cyan/[0.08] text-cyan" },
  completed: { label: "Completed", className: "border-good/25 bg-good/[0.07] text-good" },
  failed: { label: "Failed", className: "border-critical/30 bg-critical/[0.08] text-critical" },
  cancelled: { label: "Stopped", className: "border-lilac/20 bg-white/[0.03] text-lilac/55" },
};

function StageIcon({ status }: { status: ScanStage["status"] }) {
  if (status === "done") {
    return (
      <span className="flex size-5 items-center justify-center rounded-full border border-good/30 bg-good/[0.1]">
        <Check className="size-3 text-good" strokeWidth={2.5} />
      </span>
    );
  }
  if (status === "active") {
    return (
      <span className="flex size-5 items-center justify-center rounded-full border border-cyan/40 bg-cyan/[0.1]">
        <LoaderCircle className="size-3 animate-spin text-cyan" strokeWidth={2.2} />
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className="flex size-5 items-center justify-center rounded-full border border-critical/40 bg-critical/[0.1]">
        <XCircle className="size-3 text-critical" strokeWidth={2.2} />
      </span>
    );
  }
  return (
    <span className="flex size-5 items-center justify-center rounded-full border border-white/10 bg-white/[0.02]">
      <Circle className="size-2 text-lilac/25" fill="currentColor" strokeWidth={0} />
    </span>
  );
}

function ModuleDetailCard({
  check,
  state,
  result,
}: {
  check: CheckId;
  state: ModuleState;
  result?: CheckResultRecord;
}) {
  const Icon = moduleIcons[check];
  const badge = result ? checkStatusBadge[result.status] : fallbackModuleBadge[state];

  return (
    <div
      className={classNames(
        "border p-4 transition-colors",
        result?.status === "scan_failed" || state === "failed"
          ? "border-critical/30 bg-critical/[0.035]"
          : result?.status === "inconclusive"
            ? "border-medium/30 bg-medium/[0.03]"
            : result?.status === "finding_detected"
              ? "border-gold/25 bg-gold/[0.02]"
              : result?.status === "no_issue_observed"
                ? "border-good/25 bg-good/[0.02]"
                : "border-[#1a2b42] bg-[#07101d]/70",
      )}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Icon className="size-4 text-cyan/80" strokeWidth={1.7} />
          <h3 className="font-display text-[13.5px] font-medium text-paper">{moduleNames[check]}</h3>
        </div>
        <span
          className={classNames(
            "inline-flex items-center gap-1.5 rounded-[2px] border px-2 py-0.5 font-mono text-[8px] uppercase tracking-[0.1em]",
            badge.className,
          )}
        >
          {badge.label}
        </span>
      </div>

      <p className="mt-2.5 text-[11px] leading-relaxed text-lilac/65">
        {result?.summary ??
          (state === "skipped"
            ? "Module was not selected for this scan."
            : state === "running"
              ? "Executing module requests on backend..."
              : "Waiting for execution.")}
      </p>

      {result?.error ? (
        <p className="mt-2 flex items-start gap-1.5 border border-critical/25 bg-critical/[0.06] px-2.5 py-2 text-[10.5px] text-critical">
          <CircleAlert className="mt-0.5 size-3.5 shrink-0" />
          {result.error}
        </p>
      ) : null}

      {result?.observations && result.observations.length > 0 ? (
        <div className="mt-3 overflow-hidden border border-[#1a2b42] bg-[#030810]">
          <div className="border-b border-[#142338] px-3 py-1.5 font-mono text-[8px] uppercase tracking-[0.12em] text-lilac/35">
            Observed signals
          </div>
          <div className="divide-y divide-[#142338]">
            {result.observations.map((obs) => (
              <div key={`${check}-${obs.label}`} className="flex items-start justify-between gap-3 px-3 py-1.5">
                <span className="font-mono text-[9.5px] text-lilac/55">{obs.label}</span>
                <span
                  className={classNames(
                    "max-w-[60%] break-all text-right font-mono text-[9.5px]",
                    obs.state === "absent"
                      ? "text-critical/80"
                      : obs.state === "warn"
                        ? "text-gold"
                        : "text-paper/80",
                  )}
                >
                  {obs.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {result?.limitations && result.limitations.length > 0 ? (
        <div className="mt-3 space-y-1">
          {result.limitations.map((lim) => (
            <p key={lim} className="flex items-start gap-1.5 text-[9.5px] leading-relaxed text-lilac/40">
              <Info className="mt-0.5 size-3 shrink-0 text-lilac/30" />
              {lim}
            </p>
          ))}
        </div>
      ) : null}

      <div className="mt-3 flex items-center justify-between border-t border-[#142338] pt-2 font-mono text-[8px] uppercase tracking-[0.1em] text-lilac/35">
        <span>{result ? `${result.findingsCount} ${pluralize(result.findingsCount, "finding")}` : state}</span>
        <span>{result ? `${result.requestsMade} ${pluralize(result.requestsMade, "request")}` : "0 requests"}</span>
      </div>
    </div>
  );
}

function ExpandableFindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  const [tab, setTab] = useState<"observed" | "baseline" | "request">("observed");
  const statusInfo = finding.checkStatus ? checkStatusBadge[finding.checkStatus] : null;

  return (
    <div className="border border-[#1a2b42] bg-[#060d18]">
      <div className="flex flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-lilac/35">{finding.id}</span>
            <SeverityBadge severity={finding.severity} compact />
            <ConfidenceMeter confidence={finding.confidence} />
            {statusInfo ? (
              <span className={classNames("rounded-[2px] border px-1.5 py-0.5 font-mono text-[7.5px] uppercase tracking-[0.08em]", statusInfo.className)}>
                {statusInfo.label}
              </span>
            ) : null}
            <span className="font-mono text-[8.5px] text-lilac/45">{finding.moduleName}</span>
          </div>
          <p className="mt-2 text-[13px] font-medium text-paper">{finding.title}</p>
          <p className="mt-1 font-mono text-[9.5px] text-lilac/40">{finding.targetUrl ?? finding.targetPath}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            onClick={() => setExpanded((prev) => !prev)}
            className="inline-flex h-8 items-center gap-1.5 border border-cyan/25 bg-cyan/[0.05] px-3 font-mono text-[9px] uppercase tracking-[0.1em] text-cyan transition hover:border-cyan/50 hover:bg-cyan/[0.1]"
          >
            {expanded ? "Hide evidence" : "Inspect evidence"}
            {expanded ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
          </button>
          <Link
            to={`/findings/${finding.id}`}
            className="inline-flex h-8 items-center gap-1 border border-[#24374f] px-3 font-mono text-[9px] uppercase tracking-[0.1em] text-lilac/65 transition hover:border-lilac/40 hover:text-paper"
          >
            Case file
          </Link>
        </div>
      </div>

      {expanded ? (
        <div className="space-y-4 border-t border-[#142338] bg-[#040912] px-4 py-4">
          <div className="grid gap-4 lg:grid-cols-2">
            <div>
              <p className="mono-label text-lilac/40">Explanation & impact</p>
              <p className="mt-1.5 text-[11.5px] leading-relaxed text-lilac/70">{finding.summary}</p>
              <p className="mt-2 text-[11px] leading-relaxed text-lilac/50">{finding.impact}</p>
              <p className="mt-2 font-mono text-[9.5px] text-lilac/40">
                Severity rationale: {finding.severityRationale}
              </p>
              <p className="mt-1 font-mono text-[9.5px] text-lilac/40">
                Confidence rationale: {finding.confidenceRationale}
              </p>
            </div>
            <div>
              <p className="mono-label text-lilac/40">Recommended remediation</p>
              <ul className="mt-1.5 space-y-1.5">
                {finding.remediation.map((step) => (
                  <li key={step} className="flex items-start gap-2 text-[11px] leading-relaxed text-lilac/65">
                    <Check className="mt-0.5 size-3 shrink-0 text-good" />
                    {step}
                  </li>
                ))}
              </ul>
              {finding.fixSnippet ? (
                <CodeBlock
                  className="mt-3"
                  title="Fix example"
                  code={finding.fixSnippet}
                  language={finding.fixLanguage}
                  lineNumbers={false}
                  maxHeight="max-h-[160px]"
                />
              ) : null}
            </div>
          </div>

          <div>
            <div className="mb-2 flex items-center gap-1.5">
              {(["observed", ...(finding.evidence.baseline ? ["baseline"] : []), "request"] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTab(t as "observed" | "baseline" | "request")}
                  className={classNames(
                    "rounded-[2px] px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.1em] transition",
                    tab === t
                      ? "border border-cyan/30 bg-cyan/[0.08] text-cyan"
                      : "border border-transparent text-lilac/40 hover:text-lilac/70",
                  )}
                >
                  {t === "observed" ? "Observed response" : t === "baseline" ? "Baseline" : "Request"}
                </button>
              ))}
            </div>
            <CodeBlock
              code={
                tab === "baseline"
                  ? (finding.evidence.baseline ?? "")
                  : tab === "request"
                    ? finding.evidence.request
                    : finding.evidence.response
              }
              title={tab === "baseline" ? "Baseline comparison" : tab === "request" ? "HTTP request" : "Observed HTTP response"}
              language="http"
              maxHeight="max-h-[260px]"
            />
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function ScanProgress() {
  const { scanId } = useParams();
  const { getScan, getFindingsForScan, loading, backendError, refreshWorkspace } = useWorkspace();
  const scan = scanId ? getScan(scanId) : undefined;
  const scanFindings = scan ? getFindingsForScan(scan.id) : [];
  const counts = countSeverities(scanFindings);

  useEffect(() => {
    if (!scan && !loading) {
      void refreshWorkspace();
    }
  }, [loading, refreshWorkspace, scan]);

  const sortedFindings = useMemo(
    () =>
      [...scanFindings].sort(
        (a, b) =>
          severityRank(a.severity) - severityRank(b.severity) ||
          confidenceRank(a.confidence) - confidenceRank(b.confidence),
      ),
    [scanFindings],
  );

  if (loading && !scan) {
    return (
      <div className="mx-auto max-w-xl py-20 text-center">
        <LoaderCircle className="mx-auto size-8 animate-spin text-cyan" />
        <h1 className="mt-4 text-[20px] font-medium text-paper">Loading scan record...</h1>
        <p className="mt-2 text-[12px] text-lilac/45">Fetching scan telemetry and findings from SQLite.</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="mx-auto max-w-xl py-20 text-center">
        <div className="mx-auto flex size-12 items-center justify-center rounded-[3px] border border-lilac/10 bg-white/[0.02]">
          <CircleAlert className="size-5 text-lilac/40" />
        </div>
        <h1 className="mt-4 text-[22px] font-semibold tracking-[-0.02em] text-paper">Scan not found</h1>
        <p className="mx-auto mt-2 max-w-sm text-[12.5px] leading-relaxed text-lilac/45">
          {backendError ?? "This scan record was not found in the backend SQLite database."}
        </p>
        <div className="mt-6 flex justify-center gap-2">
          <Button variant="secondary" size="md" icon={RefreshCw} onClick={() => void refreshWorkspace()}>
            Retry
          </Button>
          <ButtonLink to="/scan/new" variant="primary" size="md" icon={Play}>
            New investigation
          </ButtonLink>
          <ButtonLink to="/reports" variant="secondary" size="md">
            Case records
          </ButtonLink>
        </div>
      </div>
    );
  }

  const checkResults = scan.checkResults ?? {};
  const failedCheckCount = Object.values(checkResults).filter((r) => r?.status === "scan_failed").length;
  const completedChecksCount = scan.checks.filter((c) => {
    const r = checkResults[c];
    return r && r.status !== "scan_failed";
  }).length;
  const inconclusiveCount = Object.values(checkResults).filter((r) => r?.status === "inconclusive").length;
  const isPartial = scan.status === "completed" && failedCheckCount > 0;
  const isSample = scan.dataSource === "sample";
  const status = scanStatusStyle[scan.status];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Link
          to="/reports"
          className="inline-flex items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.12em] text-lilac/35 transition hover:text-cyan"
        >
          <ArrowLeft className="size-3" /> Case records / scan results
        </Link>
        <div className="flex flex-wrap items-center gap-2">
          {isSample ? <DemoBadge label="Sample data" /> : null}
          {isPartial ? (
            <span className="inline-flex items-center gap-1.5 rounded-[2px] border border-medium/35 bg-medium/[0.09] px-2 py-1 font-mono text-[9px] uppercase tracking-[0.1em] text-medium">
              <AlertTriangle className="size-3" /> Partial scan ({failedCheckCount} module failed)
            </span>
          ) : null}
          <span className={classNames("inline-flex items-center gap-1.5 rounded-[2px] border px-2 py-1 font-mono text-[9px] uppercase tracking-[0.1em]", status.className)}>
            <span className="size-[5px] rounded-full bg-current" />
            {status.label}
          </span>
        </div>
      </div>

      <header className="flex flex-col justify-between gap-4 border-l-2 border-cyan/60 pl-4 sm:flex-row sm:items-end">
        <div>
          <p className="font-mono text-[8px] uppercase tracking-[0.16em] text-cyan/55">
            // {scan.label} / {scan.id} / {formatDateTime(scan.startedAt)}
          </p>
          <h1 className="mt-2 font-display text-[30px] font-medium leading-[0.98] tracking-[-0.045em] text-paper sm:text-[40px]">
            {scan.status === "failed"
              ? "Scan failed."
              : isPartial
                ? "Scan completed with module failure."
                : scan.status === "completed"
                  ? "Scan results & observations."
                  : "Scan running."}
          </h1>
          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-lilac/50">
            <span className="inline-flex items-center gap-1.5 font-mono text-[10.5px] text-paper/85">
              <Globe2 className="size-3 text-cyan" /> {scan.target}
            </span>
            <span className="size-[3px] rounded-full bg-lilac/20" />
            <span>{completedChecksCount}/{scan.checks.length} checks completed</span>
            <span className="size-[3px] rounded-full bg-lilac/20" />
            <span>{scan.requestCount} HTTP {pluralize(scan.requestCount, "request")}</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {scan.status === "completed" ? (
            <ButtonLink to={`/reports/${scan.id}`} variant="secondary" size="md" icon={FileText}>
              Open report
            </ButtonLink>
          ) : null}
          <ButtonLink to="/scan/new" variant="gold" size="md" icon={Play}>
            New investigation
          </ButtonLink>
        </div>
      </header>

      {/* Scan Overview */}
      <Panel className="animate-fade-up overflow-hidden">
        <div className="grid grid-cols-2 divide-x divide-y divide-[#142338] border-b border-[#1a2b42] sm:grid-cols-4 sm:divide-y-0">
          <div className="px-4 py-3.5">
            <p className="mono-label text-lilac/35">Target URL</p>
            <p className="mt-1.5 truncate font-mono text-[11px] text-paper/90" title={scan.target}>{scan.target}</p>
            <p className="mt-1 font-mono text-[8.5px] text-lilac/35">ID: {scan.id}</p>
          </div>
          <div className="px-4 py-3.5">
            <p className="mono-label text-lilac/35">Timing</p>
            <p className="mt-1.5 text-[11px] text-paper/85">{formatDateTime(scan.startedAt)}</p>
            <p className="mt-1 font-mono text-[8.5px] text-lilac/35">
              {scan.completedAt ? `Completed in ${formatDuration(scan.startedAt, scan.completedAt)}` : "In progress"}
            </p>
          </div>
          <div className="px-4 py-3.5">
            <p className="mono-label text-lilac/35">Checks completed</p>
            <p className="mt-1.5 font-display text-[24px] font-medium leading-none text-paper">
              {completedChecksCount}/{scan.checks.length}
            </p>
            <p className="mt-1 font-mono text-[8.5px] text-lilac/35">
              {failedCheckCount > 0 ? `${failedCheckCount} failed` : `${inconclusiveCount} inconclusive`}
            </p>
          </div>
          <div className="px-4 py-3.5">
            <p className="mono-label text-lilac/35">Findings</p>
            <p className="mt-1.5 font-display text-[24px] font-medium leading-none text-paper">
              {scanFindings.length}
            </p>
            <p className="mt-1 font-mono text-[8.5px] text-lilac/35">
              {scan.requestCount} HTTP requests sent
            </p>
          </div>
        </div>

        <div className="px-5 py-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <SectionLabel>Severity distribution</SectionLabel>
            <SeverityLegend counts={counts} compact />
          </div>
          <SeverityStrip counts={counts} className="mt-3" />
          {scan.error ? (
            <p className="mt-3 flex items-start gap-2 border border-critical/25 bg-critical/[0.05] px-3 py-2 text-[11px] text-critical">
              <CircleAlert className="mt-0.5 size-3.5 shrink-0" />
              {scan.error}
            </p>
          ) : null}
        </div>
      </Panel>

      {/* Four Independent Scanner Modules */}
      <Panel className="animate-fade-up delay-1 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1a2b42] bg-[#08111e]/60 px-5 py-4">
          <div>
            <SectionLabel>Module execution & observations</SectionLabel>
            <h2 className="mt-1 font-display text-[17px] font-medium text-paper">
              All four security modules
            </h2>
          </div>
          <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-lilac/40">
            Observed evidence shown even when 0 findings are detected
          </span>
        </div>
        <div className="grid gap-4 p-4 md:grid-cols-2">
          {CHECK_ORDER.map((check) => (
            <ModuleDetailCard
              key={check}
              check={check}
              state={scan.modules[check]}
              result={checkResults[check]}
            />
          ))}
        </div>
      </Panel>

      {/* Individual Findings with Expandable Evidence */}
      <Panel className="animate-fade-up delay-2 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1a2b42] bg-[#08111e]/60 px-5 py-4">
          <div>
            <SectionLabel>Detected findings & evidence</SectionLabel>
            <h2 className="mt-1 font-display text-[17px] font-medium text-paper">
              {sortedFindings.length} {pluralize(sortedFindings.length, "finding")} recorded
            </h2>
          </div>
          <Link
            to={`/findings?scan=${scan.id}`}
            className="font-mono text-[9px] uppercase tracking-[0.12em] text-cyan/75 transition hover:text-cyan"
          >
            Open in Evidence Log →
          </Link>
        </div>

        <div className="p-4">
          {scan.status === "failed" ? (
            <div className="border border-critical/25 bg-critical/[0.04] p-4">
              <p className="flex items-center gap-2 text-[12.5px] font-medium text-critical">
                <XCircle className="size-4" /> Scan failed — this is not a clean result.
              </p>
              <p className="mt-1.5 text-[11px] text-lilac/55">{scan.error}</p>
            </div>
          ) : sortedFindings.length === 0 ? (
            <div className="border border-[#1a2b42] bg-[#040a13] p-5">
              <div className="flex items-center gap-2 text-good">
                <CheckCircle2 className="size-4" />
                <p className="text-[13px] font-medium text-paper">
                  {failedCheckCount > 0 || inconclusiveCount > 0
                    ? "No confirmed findings in completed modules (check inconclusive/failed modules above)."
                    : "No vulnerabilities observed in the scoped checks."}
                </p>
              </div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-lilac/50">
                Inspect each module card above for actual observed headers, cookie status, baseline path comparison, and injection limitations. An absence of findings does not prove the entire application is secure.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {sortedFindings.map((finding) => (
                <ExpandableFindingCard key={finding.id} finding={finding} />
              ))}
            </div>
          )}
        </div>
      </Panel>

      {/* Stage Timeline & Backend Logs */}
      <div className="grid gap-5 lg:grid-cols-2">
        <Panel className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-lilac/[0.08] px-5 py-3.5">
            <SectionLabel>Execution stages</SectionLabel>
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-lilac/35">
              {scan.stages.filter((s) => s.status === "done").length}/{scan.stages.length} done
            </span>
          </div>
          <div className="px-5 py-3">
            {scan.stages.map((stage) => (
              <div key={stage.id} className="flex items-start gap-3 py-2">
                <StageIcon status={stage.status} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-[11.5px] font-medium text-paper/85">{stage.label}</p>
                    <span className="font-mono text-[8px] uppercase text-lilac/35">{stage.status}</span>
                  </div>
                  <p className="mt-0.5 text-[10px] text-lilac/40">{stage.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-lilac/[0.08] px-5 py-3.5">
            <SectionLabel>Backend execution log</SectionLabel>
            <span className="font-mono text-[8.5px] text-lilac/30">{scan.logs.length} entries</span>
          </div>
          <div className="max-h-[260px] overflow-y-auto bg-[#030810] px-4 py-3 font-mono text-[10px] leading-[1.8]">
            {scan.logs.map((line) => (
              <div key={line.id} className="flex items-start gap-2.5">
                <span className="shrink-0 text-lilac/25">
                  {new Date(line.at).toLocaleTimeString("en-GB", { hour12: false })}
                </span>
                <span
                  className={classNames(
                    "w-12 shrink-0 text-[8.5px] uppercase",
                    line.level === "success"
                      ? "text-good"
                      : line.level === "error"
                        ? "text-critical"
                        : line.level === "warn"
                          ? "text-gold"
                          : "text-cyan/70",
                  )}
                >
                  {line.level}
                </span>
                <span className="min-w-0 break-words text-lilac/65">{line.text}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="flex items-center justify-between border border-[#1a2b42] bg-[#040a13] px-4 py-3 font-mono text-[8.5px] uppercase tracking-[0.1em] text-lilac/35">
        <span className="flex items-center gap-1.5">
          <LockKeyhole className="size-3 text-good/70" /> Persisted in SQLite · {hostnameOf(scan.target)}
        </span>
        <span>{formatRelative(scan.completedAt ?? scan.startedAt)}</span>
      </div>
    </div>
  );
}
