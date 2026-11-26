import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Clock3,
  Download,
  FileDown,
  FileSearch,
  FileText,
  FlaskConical,
  LoaderCircle,
  LockKeyhole,
  Play,
  RotateCw,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useWorkspace } from "../store/WorkspaceStore";
import { useReportExport } from "../hooks/useReportExport";
import { Button, ButtonLink } from "../components/ui/Button";
import { DemoBadge, SeverityBadge, StatusBadge } from "../components/ui/Badges";
import { Panel, SectionLabel } from "../components/ui/Section";
import { CodeBlock } from "../components/ui/CodeBlock";
import { EmptyState } from "../components/ui/EmptyState";
import { LogoMark } from "../components/brand/Logo";
import {
  classNames,
  formatDate,
  formatDateTime,
  formatDuration,
  hostnameOf,
  pluralize,
  severityRank,
  statusRank,
} from "../lib/format";
import { countSeverities } from "../components/ui/SeverityDistribution";
import type { Scan, Severity } from "../types";

const statusStyle: Record<Scan["status"], { label: string; className: string }> = {
  completed: { label: "Complete", className: "border-good/25 bg-good/[0.07] text-good" },
  running: { label: "Running", className: "border-gold/30 bg-gold/[0.07] text-gold" },
  failed: { label: "Failed", className: "border-critical/25 bg-critical/[0.06] text-critical" },
  cancelled: { label: "Stopped", className: "border-lilac/15 bg-white/[0.03] text-lilac/45" },
};

const lightSeverity: Record<Severity, { text: string; border: string; bg: string; rule: string }> = {
  critical: { text: "text-[#a32948]", border: "border-[#a32948]/20", bg: "bg-[#f8e9ed]", rule: "bg-[#a32948]" },
  high: { text: "text-[#a34f16]", border: "border-[#a34f16]/20", bg: "bg-[#fbf0e7]", rule: "bg-[#a34f16]" },
  medium: { text: "text-[#7a5a0a]", border: "border-[#7a5a0a]/20", bg: "bg-[#fbf5df]", rule: "bg-[#b38b1c]" },
  low: { text: "text-[#245f7a]", border: "border-[#245f7a]/20", bg: "bg-[#eaf4f8]", rule: "bg-[#2b6f89]" },
  informational: { text: "text-[#4b5c70]", border: "border-[#4b5c70]/20", bg: "bg-[#f1f4f8]", rule: "bg-[#64748b]" },
};

function PaperHeading({
  index,
  title,
  description,
}: {
  index: string;
  title: string;
  description?: string;
}) {
  return (
    <div className="mb-4">
      <div className="flex items-center gap-2.5">
        <span className="flex size-6 items-center justify-center rounded-[3px] bg-[#0b1626] font-mono text-[8px] text-[#eaf0ff]">
          {index}
        </span>
        <span className="font-mono text-[9px] uppercase tracking-[0.14em] text-[#0b5b6b]">{title}</span>
        <span className="h-px flex-1 bg-[#0b1626]/10" />
      </div>
      {description ? (
        <p className="mt-2.5 max-w-2xl text-[11px] leading-relaxed text-[#0b1626]/55">{description}</p>
      ) : null}
    </div>
  );
}

export function ReportDetail() {
  const { scanId } = useParams();
  const { getScan, getFindingsForScan, getFinding } = useWorkspace();
  const { exportReport, exportingId } = useReportExport();
  const scan = scanId ? getScan(scanId) : undefined;

  if (!scan) {
    return (
      <div className="mx-auto max-w-xl py-20">
        <EmptyState
          icon={FileSearch}
          title="Report not found."
          description="This run is not in the local demo workspace. It may have been removed by a workspace reset."
          action={
            <ButtonLink to="/reports" variant="primary" size="md" icon={ArrowLeft}>
              Back to history
            </ButtonLink>
          }
        />
      </div>
    );
  }

  const findings = getFindingsForScan(scan.id);
  const counts = countSeverities(findings);
  const open = findings.filter((finding) => finding.status === "open").length;
  const resolved = findings.filter((finding) => finding.status === "resolved").length;
  const status = statusStyle[scan.status];
  const isVerification = Boolean(scan.rescanOfFindingId);
  const updatedFinding = scan.verification ? getFinding(scan.verification.findingId) : undefined;
  const sortedFindings = [...findings].sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      statusRank(a.status) - statusRank(b.status),
  );
  const pdfReady = scan.status === "completed";
  const exporting = exportingId === scan.id;
  const isSample = scan.dataSource === "sample";

  if (scan.status !== "completed") {
    return (
      <div className="space-y-5">
        <Link to="/reports" className="inline-flex items-center gap-1.5 text-[11px] text-lilac/40 transition hover:text-paper">
          <ArrowLeft className="size-3.5" /> Reports & history
        </Link>
        <Panel className="animate-fade-up overflow-hidden">
          <div className="border-b border-lilac/[0.08] px-5 py-5 sm:px-7">
            <div className="flex flex-wrap items-center gap-2">
              <span className={classNames("inline-flex items-center gap-1.5 rounded-[2px] border px-2 py-1 font-mono text-[9px] uppercase tracking-[0.1em]", status.className)}>
                <span className="size-[4px] rounded-full bg-current" /> {status.label}
              </span>
              <span className="font-mono text-[9px] uppercase tracking-[0.1em] text-lilac/25">{scan.id}</span>
            </div>
            <h1 className="mt-3 text-[28px] font-semibold tracking-[-0.035em] text-paper sm:text-[34px]">
              Report not available for this run.
            </h1>
            <p className="mt-2 max-w-xl text-[12.5px] leading-relaxed text-lilac/50">
              {scan.status === "failed"
                ? "This scan failed before completion. The failure record is preserved in SQLite history, and no findings report is available."
                : "The run was stopped before completion. A signed-off report can only be generated from a completed scan."}
            </p>
            <div className="mt-5 flex flex-wrap gap-2">
              <ButtonLink to={`/scans/${scan.id}/progress`} variant="primary" size="md" icon={Play}>
                View run details
              </ButtonLink>
              <ButtonLink to="/scan/new" variant="secondary" size="md" icon={RotateCw}>
                Start another scan
              </ButtonLink>
            </div>
          </div>
          <div className="grid gap-0 border-b border-lilac/[0.08] sm:grid-cols-3">
            <div className="border-b border-lilac/[0.07] px-5 py-4 sm:border-b-0 sm:border-r">
              <p className="mono-label text-lilac/30">Target</p>
              <p className="mt-1.5 font-mono text-[11px] text-lilac/65">{scan.target}</p>
            </div>
            <div className="border-b border-lilac/[0.07] px-5 py-4 sm:border-b-0 sm:border-r">
              <p className="mono-label text-lilac/30">Started</p>
              <p className="mt-1.5 text-[11px] text-lilac/65">{formatDateTime(scan.startedAt)}</p>
            </div>
            <div className="px-5 py-4">
              <p className="mono-label text-lilac/30">Elapsed</p>
              <p className="mt-1.5 font-mono text-[11px] text-lilac/65">{formatDuration(scan.startedAt, scan.completedAt)}</p>
            </div>
          </div>
          <div className="border-t border-critical/15 bg-critical/[0.035] px-5 py-4">
            <p className="flex items-start gap-2 text-[11.5px] leading-relaxed text-critical/90">
              <CircleAlert className="mt-0.5 size-3.5 shrink-0" />
              {scan.error ?? "This run ended before findings were generated."}
            </p>
          </div>
        </Panel>
      </div>
    );
  }

  const lead = scan.verification
    ? "This verification run re-checked one previously recorded observation. It intentionally does not produce a new finding set."
    : findings.length > 0
      ? `This review recorded ${findings.length} ${pluralize(findings.length, "finding")} across ${scan.checks.length} selected ${pluralize(scan.checks.length, "module")}. Each finding is paired with its raw observation, a separate risk interpretation and a remediation step.`
      : "This run produced no findings in the selected modules. A clean result is not proof that the application is secure; scope and method still matter.";

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Link to="/reports" className="inline-flex items-center gap-1.5 text-[11px] text-lilac/40 transition hover:text-paper">
          <ArrowLeft className="size-3.5" /> Reports & history
        </Link>
        <div className="flex items-center gap-2">
          {isSample ? <DemoBadge label="Sample report data" subtle /> : null}
          <span className={classNames("inline-flex items-center gap-1.5 rounded-[2px] border px-2 py-1 font-mono text-[9px] uppercase tracking-[0.1em]", status.className)}>
            <span className="size-[4px] rounded-full bg-current" /> {status.label}
          </span>
        </div>
      </div>

      <header className="animate-fade-up flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <div className="min-w-0">
          <p className="mono-label text-lilac/40">
            {scan.label} · {scan.id} · {formatDate(scan.startedAt)}
          </p>
          <h1 className="mt-2 text-[27px] font-semibold leading-[1.05] tracking-[-0.035em] text-paper sm:text-[34px]">
            {isVerification ? "Verification report." : "Security evidence report."}
          </h1>
          <p className="mt-2 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11.5px] text-lilac/40">
            <span className="font-mono text-[10.5px] text-lilac/65">{scan.target}</span>
            <span className="size-[3px] rounded-full bg-lilac/20" />
            <span>{scan.checks.length} {pluralize(scan.checks.length, "module")}</span>
            <span className="size-[3px] rounded-full bg-lilac/20" />
            <span>{isVerification ? "One observation re-checked" : `${findings.length} ${pluralize(findings.length, "finding")}`}</span>
            <span className="size-[3px] rounded-full bg-lilac/20" />
            <span>{formatDuration(scan.startedAt, scan.completedAt)}</span>
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="gold"
            size="md"
            icon={exporting ? LoaderCircle : Download}
            onClick={() => void exportReport(scan, findings)}
            loading={exporting}
            disabled={!pdfReady}
          >
            Download PDF
          </Button>
          <ButtonLink
            to={updatedFinding ? `/findings/${updatedFinding.id}` : `/findings?scan=${scan.id}`}
            variant="secondary"
            size="md"
            icon={FileSearch}
          >
            {updatedFinding ? "View updated finding" : "View findings"}
          </ButtonLink>
        </div>
      </header>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="overflow-hidden rounded-[3px] border border-lilac/[0.1] bg-[#07101d]/70 px-4 py-3.5">
          <p className="mono-label text-lilac/30">Findings in report</p>
          <p className="mt-2 text-[24px] font-semibold leading-none tracking-[-0.03em] text-paper">
            {isVerification ? "0" : findings.length}
          </p>
          <p className="mt-1.5 text-[9.5px] text-lilac/25">{isVerification ? "verification records only" : `${open} open · ${resolved} resolved`}</p>
        </div>
        <div className="overflow-hidden rounded-[3px] border border-lilac/[0.1] bg-[#07101d]/70 px-4 py-3.5">
          <p className="mono-label text-lilac/30">{isVerification ? "Rescan result" : "Critical / high"}</p>
          {isVerification && scan.verification ? (
            <p className={classNames("mt-2 text-[16px] font-semibold tracking-[-0.02em]", scan.verification.outcome === "resolved" ? "text-good" : "text-gold")}>
              {scan.verification.outcome === "resolved" ? "Resolved" : "Still present"}
            </p>
          ) : (
            <p className="mt-2 text-[24px] font-semibold leading-none tracking-[-0.03em] text-paper">
              {counts.critical + counts.high}
            </p>
          )}
          <p className="mt-1.5 text-[9.5px] text-lilac/25">
            {isVerification ? scan.verification?.findingId : "requires immediate review"}
          </p>
        </div>
        <div className="overflow-hidden rounded-[3px] border border-lilac/[0.1] bg-[#07101d]/70 px-4 py-3.5">
          <p className="mono-label text-lilac/30">Checks completed</p>
          <p className="mt-2 text-[24px] font-semibold leading-none tracking-[-0.03em] text-paper">
            {scan.checks.length}
          </p>
          <p className="mt-1.5 text-[9.5px] text-lilac/25">
            {isSample ? "sample evidence" : "SQLite persisted record"}
          </p>
        </div>
        <div className="overflow-hidden rounded-[3px] border border-lilac/[0.1] bg-[#07101d]/70 px-4 py-3.5">
          <p className="mono-label text-lilac/30">PDF format</p>
          <p className="mt-2 text-[16px] font-semibold leading-none tracking-[-0.02em] text-paper">A4 · multi-page</p>
          <p className="mt-1.5 text-[9.5px] text-lilac/25">generated locally · print-ready</p>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_310px]">
        <article className="report-paper animate-fade-up overflow-hidden rounded-[3px] border border-[#0b1626]/15 shadow-[0_24px_80px_rgba(0,0,0,0.28)]">
          <div className="relative overflow-hidden bg-[#050711] px-5 py-6 text-paper sm:px-8 sm:py-7">
            <img src="/brand/city-night.jpg" alt="" aria-hidden="true" className="absolute inset-0 h-full w-full object-cover object-[52%_52%] opacity-25" />
            <div className="absolute inset-0 bg-gradient-to-r from-[#050711] via-[#050711]/92 to-[#050711]/45" />
            <div className="relative">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <LogoMark size={32} />
                  <div>
                    <p className="text-[12px] font-semibold uppercase tracking-[0.15em] text-paper">Bug Hunter Lab</p>
                    <p className="mt-1 font-mono text-[8px] uppercase tracking-[0.18em] text-lilac/40">Evidence-first security review</p>
                  </div>
                </div>
                <span className="rounded-[3px] border border-gold/35 px-2 py-1 font-mono text-[8px] uppercase tracking-[0.12em] text-gold">
                  {isSample ? "Sample data" : "Live scan record"}
                </span>
              </div>

              <p className="mt-8 font-mono text-[8.5px] uppercase tracking-[0.18em] text-lavender/70">
                RAVENX 2026 / PS-4 / Security evidence report
              </p>
              <h2 className="mt-2 max-w-lg text-[26px] font-semibold leading-[1.02] tracking-[-0.04em] sm:text-[32px]">
                {isVerification ? "Verification record" : "Security evidence"}
                <br />
                {isVerification ? "for one finding" : "report"}
              </h2>
              <div className="mt-5 flex flex-wrap items-center gap-3">
                <span className="font-mono text-[11px] text-paper/85">{hostnameOf(scan.target)}</span>
                <span className="size-[3px] rounded-full bg-lilac/30" />
                <span className="font-mono text-[9px] uppercase tracking-[0.08em] text-lilac/45">{scan.label}</span>
                <span className="size-[3px] rounded-full bg-lilac/30" />
                <span className="font-mono text-[9px] uppercase tracking-[0.08em] text-lilac/45">{scan.id}</span>
              </div>
            </div>
          </div>

          <div className="px-5 py-6 sm:px-8 sm:py-7">
            <PaperHeading
              index="01"
              title={isVerification ? "Verification summary" : "Executive summary"}
              description={isVerification ? undefined : "A concise record of what was checked, what was observed and what remains to be verified."}
            />
            <p className="max-w-2xl text-[12px] leading-relaxed text-[#0b1626]/70">{lead}</p>

            {isVerification && scan.verification ? (
              <div className="mt-5">
                <div
                  className={classNames(
                    "rounded-[2px] border px-4 py-3.5",
                    scan.verification.outcome === "resolved"
                      ? "border-[#1e7a53]/25 bg-[#eaf6ef]"
                      : "border-[#b38b1c]/25 bg-[#fbf5df]",
                  )}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span
                      className={classNames(
                        "inline-flex items-center gap-1.5 rounded-[3px] border px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-[0.08em]",
                        scan.verification.outcome === "resolved"
                          ? "border-[#1e7a53]/25 bg-white/50 text-[#1e7a53]"
                          : "border-[#b38b1c]/30 bg-white/50 text-[#7a5a0a]",
                      )}
                    >
                      {scan.verification.outcome === "resolved" ? <CheckCircle2 className="size-2.5" /> : <CircleAlert className="size-2.5" />}
                      {scan.verification.outcome === "resolved" ? "Resolved" : "Still present"}
                    </span>
                    <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-[#0b1626]/40">
                      checked {formatDate(scan.completedAt ?? scan.startedAt)}
                    </span>
                  </div>
                  <p className="mt-2.5 text-[13px] font-semibold leading-snug text-[#0b1626]">
                    {scan.verification.findingTitle}
                  </p>
                  <p className="mt-1.5 text-[10.5px] leading-relaxed text-[#0b1626]/55">{scan.verification.note}</p>
                  {updatedFinding ? (
                    <Link
                      to={`/findings/${updatedFinding.id}`}
                      className="mt-3 inline-flex items-center gap-1 text-[10px] font-medium text-[#0b5b6b] transition hover:text-[#0b1626]"
                    >
                      Open updated finding {updatedFinding.id} <ArrowRight className="size-3" />
                    </Link>
                  ) : null}
                </div>

                <div className="mt-4 grid gap-2 lg:grid-cols-2">
                  <CodeBlock code={scan.verification.before} title="Before" tone="paper" maxHeight="max-h-[180px]" lineNumbers={false} showCopy={false} />
                  <CodeBlock code={scan.verification.after} title="After" tone="paper" maxHeight="max-h-[180px]" lineNumbers={false} showCopy={false} />
                </div>
              </div>
            ) : (
              <div className="mt-5 grid grid-cols-2 gap-2 sm:grid-cols-4">
                {(["critical", "high", "medium", "low"] as Severity[]).map((severity) => (
                  <div
                    key={severity}
                    className={classNames("overflow-hidden rounded-[2px] border px-3 py-2.5", lightSeverity[severity].border, lightSeverity[severity].bg)}
                  >
                    <p className={classNames("font-mono text-[8px] uppercase tracking-[0.1em]", lightSeverity[severity].text)}>{severity}</p>
                    <p className="mt-1.5 text-[22px] font-semibold leading-none tracking-[-0.03em] text-[#0b1626]">{counts[severity]}</p>
                    <p className="mt-1 text-[8.5px] text-[#0b1626]/35">findings</p>
                  </div>
                ))}
              </div>
            )}

            <div className="mt-6 grid gap-x-6 gap-y-4 border-t border-[#0b1626]/10 pt-4 sm:grid-cols-2">
              <div>
                <p className="font-mono text-[8px] uppercase tracking-[0.12em] text-[#0b5b6b]/55">Target</p>
                <p className="mt-1 font-mono text-[10px] text-[#0b1626]/80">{scan.target}</p>
              </div>
              <div>
                <p className="font-mono text-[8px] uppercase tracking-[0.12em] text-[#0b5b6b]/55">Scan</p>
                <p className="mt-1 text-[10px] text-[#0b1626]/80">{scan.label} · {scan.id}</p>
              </div>
              <div>
                <p className="font-mono text-[8px] uppercase tracking-[0.12em] text-[#0b5b6b]/55">Completed</p>
                <p className="mt-1 text-[10px] text-[#0b1626]/80">{scan.completedAt ? formatDateTime(scan.completedAt) : "—"}</p>
              </div>
              <div>
                <p className="font-mono text-[8px] uppercase tracking-[0.12em] text-[#0b5b6b]/55">Data source</p>
                <p className="mt-1 text-[10px] text-[#0b1626]/80">
                  {isSample ? "Sample data" : "FastAPI + SQLite (live scan)"}
                </p>
              </div>
            </div>

            <div className="mt-6 border-t border-[#0b1626]/10 pt-5">
              <PaperHeading index="02" title={isVerification ? "Scope note" : "Coverage"} />
              {isVerification ? (
                <p className="max-w-2xl text-[11px] leading-relaxed text-[#0b1626]/60">
                  This run checked one module for one observed finding. A resolved marker means the specific recorded evidence changed; it does not prove the whole application is secure. The original finding record and this verification run are preserved in history.
                </p>
              ) : (
                <div className="space-y-2">
                  {[
                    ["HTTP Header Inspector", "CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy", "headers"],
                    ["Cookie Security Analyzer", "Secure, HttpOnly, SameSite", "cookies"],
                    ["Exposed Path Detector", "Allowlisted paths with baseline comparison", "paths"],
                    ["Injection Vulnerability Tester", "Low-impact probes with baseline comparison", "injection"],
                  ].map(([title, description, id]) => {
                    const checked = scan.checks.includes(id as never);
                    const count = findings.filter((finding) => finding.category === id).length;
                    return (
                      <div key={id} className="flex flex-wrap items-center justify-between gap-2 border-b border-[#0b1626]/[0.06] py-2 last:border-0">
                        <div className="flex items-center gap-2.5">
                          <span className={classNames("size-[5px] rounded-full", checked ? "bg-[#1e7a53]" : "bg-[#0b1626]/20")} />
                          <span className="text-[10.5px] font-medium text-[#0b1626]/80">{title}</span>
                          <span className="hidden text-[9.5px] text-[#0b1626]/40 sm:inline">{description}</span>
                        </div>
                        <span className="font-mono text-[8.5px] uppercase tracking-[0.05em] text-[#0b1626]/45">
                          {checked ? `${count} finding${count === 1 ? "" : "s"}` : "not selected"}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {!isVerification ? (
              <div className="mt-6 border-t border-[#0b1626]/10 pt-5">
                <div className="flex items-end justify-between gap-3">
                  <PaperHeading index="03" title="Findings index" />
                  <span className="mb-4 shrink-0 font-mono text-[8.5px] uppercase tracking-[0.08em] text-[#0b1626]/35">
                    severity, then status
                  </span>
                </div>
                {sortedFindings.length > 0 ? (
                  <div>
                    {sortedFindings.map((finding) => (
                      <Link
                        key={finding.id}
                        to={`/findings/${finding.id}`}
                        className="group flex items-center gap-3 border-b border-[#0b1626]/[0.07] py-3 last:border-0"
                      >
                        <span className="w-12 shrink-0 font-mono text-[8px] text-[#0b1626]/35">{finding.id}</span>
                        <span className={classNames("inline-flex shrink-0 rounded-[3px] border px-1.5 py-0.5 font-mono text-[7.5px] uppercase tracking-[0.06em]", lightSeverity[finding.severity].border, lightSeverity[finding.severity].bg, lightSeverity[finding.severity].text)}>
                          {finding.severity}
                        </span>
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-[10.5px] font-medium text-[#0b1626]/80 transition group-hover:text-[#0b1626]">{finding.title}</p>
                          <p className="mt-0.5 truncate font-mono text-[8px] text-[#0b1626]/35">{finding.targetPath}</p>
                        </div>
                        <span className="hidden shrink-0 text-[8.5px] uppercase tracking-[0.05em] text-[#0b1626]/35 sm:block">{finding.status}</span>
                        <ChevronRight className="size-3 shrink-0 text-[#0b1626]/20 transition group-hover:translate-x-0.5 group-hover:text-[#0b5b6b]" />
                      </Link>
                    ))}
                  </div>
                ) : (
                  <p className="rounded-[2px] border border-dashed border-[#0b1626]/15 px-3.5 py-4 text-[10.5px] text-[#0b1626]/45">
                    No findings were recorded for this run.
                  </p>
                )}
              </div>
            ) : null}

            {isSample ? (
              <div className="mt-6 rounded-[2px] border border-[#b38b1c]/25 bg-[#fbf5df] px-3.5 py-3">
                <p className="font-mono text-[8px] font-bold uppercase tracking-[0.1em] text-[#7a5a0a]">Sample data disclaimer</p>
                <p className="mt-1 text-[9.5px] leading-relaxed text-[#0b1626]/55">
                  This record is marked as illustrative sample data.
                </p>
              </div>
            ) : (
              <div className="mt-6 rounded-[2px] border border-[#0b5b6b]/20 bg-[#eaf4f8] px-3.5 py-3">
                <p className="font-mono text-[8px] font-bold uppercase tracking-[0.1em] text-[#0b5b6b]">Scan scope & limitations</p>
                <p className="mt-1 text-[9.5px] leading-relaxed text-[#0b1626]/65">
                  Generated from a real SQLite-persisted scan record ({scan.requestCount} HTTP request{scan.requestCount === 1 ? "" : "s"}). Zero findings in this report does not prove the target is completely secure.
                </p>
              </div>
            )}

            <div className="mt-5 flex flex-wrap items-center justify-between gap-2 border-t border-[#0b1626]/10 pt-3">
              <span className="font-mono text-[7.5px] uppercase tracking-[0.1em] text-[#0b1626]/35">RAVENX 2026 · Team Masala Dosa · GLA University, Mathura</span>
              <span className="font-mono text-[7.5px] uppercase tracking-[0.1em] text-[#0b1626]/35">Bug Hunter Lab</span>
            </div>
          </div>
        </article>

        <aside className="space-y-4 xl:sticky xl:top-[78px] xl:self-start">
          <Panel raised className="animate-fade-up overflow-hidden">
            <div className="border-b border-lilac/[0.08] px-4 py-4">
              <div className="flex items-center justify-between">
                <p className="mono-label text-lilac/35">Export</p>
                <span className={classNames("inline-flex items-center gap-1 font-mono text-[8px] uppercase tracking-[0.08em]", pdfReady ? "text-good" : "text-lilac/30")}>
                  {pdfReady ? <CheckCircle2 className="size-3" /> : <CircleAlert className="size-3" />}
                  {pdfReady ? "Ready" : "Unavailable"}
                </span>
              </div>
              <div className="mt-3 flex items-start gap-3">
                <div className="flex size-9 shrink-0 items-center justify-center rounded-[2px] border border-gold/20 bg-gold/[0.06]">
                  <FileDown className="size-4 text-gold/80" />
                </div>
                <div>
                  <p className="text-[12px] font-medium text-paper">Evidence report PDF</p>
                  <p className="mt-0.5 text-[9.5px] leading-relaxed text-lilac/35">
                    A4, multi-page, generated in your browser. Cover, summary, findings and verification evidence.
                  </p>
                </div>
              </div>
              <Button
                variant="gold"
                size="md"
                icon={exporting ? LoaderCircle : Download}
                className="mt-3.5 w-full"
                onClick={() => void exportReport(scan, findings)}
                loading={exporting}
                disabled={!pdfReady}
              >
                Download PDF
              </Button>
              <p className="mt-2 text-center font-mono text-[8px] uppercase tracking-[0.08em] text-lilac/25">
                0 network requests · local generation
              </p>
            </div>
            <div className="px-4 py-4">
              <p className="mono-label text-lilac/35">Inside this report</p>
              <ol className="mt-2.5 space-y-2">
                {[
                  "Cover & sample disclaimer",
                  "Executive summary",
                  "Scan scope & coverage",
                  isVerification ? "Verification before / after" : "Findings index & evidence",
                  isVerification ? "Scope limitations" : "Remediation & verification",
                ].map((item, index) => (
                  <li key={item} className="flex items-center gap-2 text-[10px] text-lilac/40">
                    <span className="font-mono text-[8px] text-gold/60">{String(index + 1).padStart(2, "0")}</span>
                    {item}
                  </li>
                ))}
              </ol>
            </div>
          </Panel>

          <Panel className="animate-fade-up delay-1 overflow-hidden">
            <div className="border-b border-lilac/[0.08] px-4 py-3.5">
              <p className="mono-label text-lilac/35">Source run</p>
            </div>
            <div className="space-y-3 px-4 py-4">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10.5px] text-lilac/35">Status</span>
                <span className={classNames("font-mono text-[9px] uppercase tracking-[0.06em]", scan.status === "completed" ? "text-good" : "text-lilac/40")}>{status.label}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10.5px] text-lilac/35">Started</span>
                <span className="text-[10px] text-lilac/55">{formatDateTime(scan.startedAt)}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10.5px] text-lilac/35">Duration</span>
                <span className="font-mono text-[10px] text-lilac/55">{formatDuration(scan.startedAt, scan.completedAt)}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10.5px] text-lilac/35">Data</span>
                <span className="font-mono text-[9px] uppercase tracking-[0.05em] text-cyan/80">
                  {isSample ? "sample" : "live sqlite"}
                </span>
              </div>
              <Link
                to={`/scans/${scan.id}/progress`}
                className="mt-1 flex h-8 w-full items-center justify-center gap-1.5 rounded-[2px] border border-lilac/12 text-[10px] text-lilac/50 transition hover:border-lilac/25 hover:text-paper"
              >
                Open source run <ArrowRight className="size-3" />
              </Link>
            </div>
          </Panel>

          <div className="animate-fade-up delay-2 rounded-[3px] border border-cyan/15 bg-cyan/[0.03] p-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-3.5 text-cyan/70" />
              <p className="mono-label text-cyan/75">Report integrity</p>
            </div>
            <p className="mt-2 text-[10px] leading-relaxed text-lilac/40">
              {isSample
                ? "This record is marked as sample data."
                : "This report is generated directly from the persisted SQLite scan record and its real findings."}
            </p>
          </div>
        </aside>
      </div>
    </div>
  );
}
