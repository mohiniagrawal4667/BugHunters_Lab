import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Clock3,
  Copy,
  FileSearch,
  FileText,
  Fingerprint,
  Info,
  Layers,
  Link2,
  LockKeyhole,
  RefreshCw,
  RotateCw,
  ScanLine,
  ShieldCheck,
  Sparkles,
  Target,
  TerminalSquare,
  Wrench,
  X,
  XCircle,
} from "lucide-react";
import { useWorkspace } from "../store/WorkspaceStore";
import { useToast } from "../components/ui/Toast";
import { Button, ButtonLink } from "../components/ui/Button";
import {
  ConfidenceMeter,
  DemoBadge,
  SeverityBadge,
  StatusBadge,
} from "../components/ui/Badges";
import { Panel, PanelHeader, SectionLabel } from "../components/ui/Section";
import { CodeBlock } from "../components/ui/CodeBlock";
import { Modal } from "../components/ui/Modal";
import { EmptyState } from "../components/ui/EmptyState";
import { copyTextToClipboard } from "../lib/clipboard";
import {
  CONFIDENCE_LABEL,
  SEVERITY_LABEL,
  STATUS_LABEL,
  classNames,
  formatDate,
  formatDateTime,
  formatRelative,
  pluralize,
  severityRank,
} from "../lib/format";
import type { EvidenceComparisonRow, Finding } from "../types";

type EvidenceTab = "observed" | "baseline" | "request";

const severityAccent = {
  critical: "from-critical/70 via-critical/20 to-transparent",
  high: "from-high/70 via-high/20 to-transparent",
  medium: "from-medium/70 via-medium/20 to-transparent",
  low: "from-low/70 via-low/20 to-transparent",
  informational: "from-lilac/40 via-lilac/15 to-transparent",
};

const verdictStyle: Record<
  EvidenceComparisonRow["verdict"],
  { label: string; className: string; icon: typeof Check }
> = {
  pass: { label: "Pass", className: "text-good", icon: CheckCircle2 },
  fail: { label: "Fail", className: "text-critical", icon: XCircle },
  warn: { label: "Warn", className: "text-gold", icon: AlertTriangle },
  info: { label: "Info", className: "text-lilac/45", icon: Info },
};

const checkStateStyle = {
  pass: { className: "border-good/25 bg-good/[0.06] text-good", icon: CheckCircle2 },
  warn: { className: "border-gold/25 bg-gold/[0.06] text-gold", icon: AlertTriangle },
  fail: { className: "border-critical/25 bg-critical/[0.06] text-critical", icon: XCircle },
};

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <p className="mono-label text-lilac/30">{label}</p>
      <div className="mt-1.5">{children}</div>
    </div>
  );
}

function RescanModal({
  finding,
  open,
  onClose,
  onConfirm,
}: {
  finding: Finding;
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Start a verification rescan?"
      description="Re-run only the module that produced this finding and compare the fresh observation with the recorded evidence."
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="gold" size="sm" icon={RefreshCw} onClick={onConfirm}>
            Start verification rescan
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="rounded-[2px] border border-lilac/12 bg-white/[0.02] p-3.5">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={finding.severity} compact />
            <span className="font-mono text-[9px] uppercase tracking-[0.08em] text-lilac/30">
              {finding.id}
            </span>
          </div>
          <p className="mt-2 text-[12.5px] font-medium text-paper/90">{finding.title}</p>
          <p className="mt-1 font-mono text-[9.5px] text-lilac/35">{finding.targetPath}</p>
        </div>

        <div>
          <p className="mono-label text-lilac/35">The rescan will</p>
          <ul className="mt-2 space-y-2">
            {[
              `Re-run the ${finding.moduleName} against the same target.`,
              "Record a new before-and-after observation against this finding.",
              "Mark the finding resolved only if the specific evidence is gone.",
              "Keep the original evidence and this verification run in history.",
            ].map((item) => (
              <li key={item} className="flex items-start gap-2 text-[11px] leading-relaxed text-lilac/50">
                <Check className="mt-0.5 size-3 shrink-0 text-good/70" />
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div className="rounded-[2px] border border-gold/20 bg-gold/[0.04] px-3.5 py-3">
          <p className="flex items-center gap-1.5 text-[10.5px] font-medium text-gold/85">
            <Info className="size-3" /> Demo behavior
          </p>
          <p className="mt-1 text-[10.5px] leading-relaxed text-lilac/40">
            No requests are sent. The local demo returns a scripted verification result and labels
            the updated record as sample data. A live backend will use the real rescan result.
          </p>
        </div>
      </div>
    </Modal>
  );
}

export function FindingDetail() {
  const { findingId } = useParams();
  const navigate = useNavigate();
  const { push } = useToast();
  const { getFinding, getScan, getFindingsForScan, rescanFinding } = useWorkspace();
  const finding = findingId ? getFinding(findingId) : undefined;
  const [tab, setTab] = useState<EvidenceTab>("observed");
  const [rescanOpen, setRescanOpen] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied">("idle");

  useEffect(() => {
    setTab("observed");
    setRescanOpen(false);
  }, [findingId]);

  useEffect(() => {
    if (copyState !== "copied") return;
    const timer = window.setTimeout(() => setCopyState("idle"), 1800);
    return () => window.clearTimeout(timer);
  }, [copyState]);

  const sourceScan = finding ? getScan(finding.scanId) : undefined;
  const related = useMemo(() => {
    if (!finding) return [];
    return getFindingsForScan(finding.scanId)
      .filter((item) => item.id !== finding.id && item.category === finding.category)
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
      .slice(0, 3);
  }, [finding, getFindingsForScan]);

  if (!finding) {
    return (
      <div className="mx-auto max-w-xl py-20">
        <EmptyState
          icon={FileSearch}
          title="Finding not found."
          description="This finding is not in the local demo workspace. It may belong to a scan that was reset or replaced."
          action={
            <ButtonLink to="/findings" variant="primary" size="md" icon={ArrowLeft}>
              Back to findings
            </ButtonLink>
          }
        />
      </div>
    );
  }

  const hasBaseline = Boolean(finding.evidence.baseline);
  const evidenceTabs: { id: EvidenceTab; label: string }[] = [
    { id: "observed", label: "Observed response" },
    ...(hasBaseline ? [{ id: "baseline" as EvidenceTab, label: "Baseline" }] : []),
    { id: "request", label: "Request" },
  ];
  const activeCode =
    tab === "baseline"
      ? finding.evidence.baseline ?? ""
      : tab === "request"
        ? finding.evidence.request
        : finding.evidence.response;
  const verification = finding.verification;
  const verified = verification.status !== "not-verified";
  const verificationLabel =
    verification.status === "verified-resolved"
      ? "Verified resolved"
      : verification.status === "verified-open"
        ? "Still present"
        : "Not yet verified";
  const verificationTone =
    verification.status === "verified-resolved"
      ? "good"
      : verification.status === "verified-open"
        ? "warn"
        : "muted";

  function startRescan() {
    if (!finding) return;
    const result = rescanFinding(finding.id);
    setRescanOpen(false);
    if (!result.ok || !result.scanId) {
      push({
        tone: "error",
        title: "Could not start the rescan",
        description: result.error ?? "The demo workspace rejected the rescan.",
      });
      return;
    }
    push({
      tone: "info",
      title: "Verification rescan started",
      description: "Re-running one module locally. No network requests are sent.",
    });
    navigate(`/scans/${result.scanId}/progress`);
  }

  async function copyFindingLink() {
    const success = await copyTextToClipboard(window.location.href);
    if (success) {
      setCopyState("copied");
      push({ tone: "success", title: "Finding link copied", description: "The local route is on your clipboard." });
    } else {
      push({ tone: "error", title: "Could not copy the link", description: "Your browser blocked clipboard access." });
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <nav className="flex flex-wrap items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.12em] text-lilac/35" aria-label="Breadcrumb">
          <Link to="/findings" className="inline-flex items-center gap-1 transition hover:text-cyan">
            <ArrowLeft className="size-3" /> Evidence log
          </Link>
          <ChevronRight className="size-3 text-lilac/20" />
          <span className="font-mono text-lilac/55">{finding.id}</span>
          <ChevronRight className="size-3 text-lilac/20" />
          <span className="truncate">{finding.categoryLabel}</span>
        </nav>
        <div className="flex items-center gap-2">
          {finding.sample ? <DemoBadge label="Sample finding" subtle /> : null}
          {sourceScan ? (
            <Link
              to={`/reports/${sourceScan.id}`}
              className="inline-flex items-center gap-1.5 text-[10.5px] text-lilac/40 transition hover:text-paper"
            >
              <FileText className="size-3" /> Scan report
            </Link>
          ) : null}
        </div>
      </div>

      <Panel className="animate-fade-up relative overflow-hidden">
        <div className={classNames("absolute inset-x-0 top-0 h-px bg-gradient-to-r", severityAccent[finding.severity])} />
        <div className="px-5 py-5 sm:px-6 sm:py-6">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-lilac/35">
              {finding.id}
            </span>
            <span className="size-[2px] rounded-full bg-lilac/20" />
            <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-lilac/45">
              {finding.categoryLabel}
            </span>
            <span className="size-[2px] rounded-full bg-lilac/20" />
            <SeverityBadge severity={finding.severity} compact />
            <StatusBadge status={finding.status} />
          </div>

          <h1 className="mt-3 max-w-4xl text-balance font-display text-[30px] font-medium leading-[1.02] tracking-[-0.05em] text-paper sm:text-[38px]">
            {finding.title}
          </h1>
          <p className="mt-3 max-w-3xl text-pretty text-[12.5px] leading-relaxed text-lilac/55 sm:text-[13px]">
            {finding.summary}
          </p>

          <div className="mt-5 grid gap-4 border-y border-[#1a2b42] bg-[#040a13]/60 px-4 py-3.5 sm:grid-cols-2 lg:grid-cols-4">
            <Field label="Target path">
              <p className="truncate font-mono text-[10.5px] text-lilac/75">{finding.targetPath}</p>
            </Field>
            <Field label="Detected">
              <p className="text-[11px] text-lilac/65">{formatDateTime(finding.detectedAt)}</p>
            </Field>
            <Field label="Source scan">
              {sourceScan ? (
                <Link
                  to={`/scans/${sourceScan.id}/progress`}
                  className="inline-flex items-center gap-1 text-[11px] text-cyan/75 transition hover:text-cyan"
                >
                  {sourceScan.label} <ArrowUpRight className="size-3" />
                </Link>
              ) : (
                <span className="text-[11px] text-lilac/40">Demo record</span>
              )}
            </Field>
            <Field label="Verification">
              <span
                className={classNames(
                  "inline-flex items-center gap-1.5 text-[10.5px]",
                  verificationTone === "good"
                    ? "text-good"
                    : verificationTone === "warn"
                      ? "text-gold"
                      : "text-lilac/40",
                )}
              >
                {verified ? <ShieldCheck className="size-3" /> : <Clock3 className="size-3" />}
                {verificationLabel}
              </span>
            </Field>
          </div>

          <div className="mt-5 flex flex-wrap items-center gap-2">
            <Button variant="gold" size="md" icon={RefreshCw} onClick={() => setRescanOpen(true)}>
              Rescan to verify
            </Button>
            {sourceScan ? (
              <ButtonLink to={`/reports/${sourceScan.id}`} variant="secondary" size="md" icon={FileText}>
                Open scan report
              </ButtonLink>
            ) : null}
            <button
              type="button"
              onClick={copyFindingLink}
              className="inline-flex h-9 items-center gap-1.5 rounded-[2px] px-3 text-[11px] text-lilac/45 transition hover:bg-white/[0.04] hover:text-paper"
            >
              {copyState === "copied" ? <Check className="size-3.5 text-good" /> : <Link2 className="size-3.5" />}
              {copyState === "copied" ? "Link copied" : "Copy finding link"}
            </button>
          </div>
        </div>
      </Panel>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-5">
          <Panel className="animate-fade-up delay-1 overflow-hidden">
            <PanelHeader
              eyebrow="01 / Observed evidence"
              title="What the scanner actually saw."
              description="Raw observation first. Nothing on this panel is an interpretation or a guess."
              action={finding.sample ? <DemoBadge label="Illustrative capture" subtle /> : undefined}
            />
            <div className="px-5 py-4">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-lilac/[0.08] pb-3">
                <div className="flex items-center gap-1" role="tablist" aria-label="Evidence views">
                  {evidenceTabs.map((item) => (
                    <button
                      key={item.id}
                      role="tab"
                      aria-selected={tab === item.id}
                      onClick={() => setTab(item.id)}
                      className={classNames(
                        "rounded-[2px] px-2.5 py-1.5 text-[10.5px] transition",
                        tab === item.id
                          ? "border border-cyan/20 bg-cyan/[0.07] text-cyan"
                          : "border border-transparent text-lilac/35 hover:bg-white/[0.03] hover:text-lilac/70",
                      )}
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-2 font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                  <Fingerprint className="size-3" />
                  {finding.fingerprint}
                </div>
              </div>

              <div className="mt-3">
                <CodeBlock
                  code={activeCode}
                  title={
                    tab === "observed"
                      ? "Observed response"
                      : tab === "baseline"
                        ? "Baseline capture"
                        : "Scanner request"
                  }
                  language="http"
                  meta={tab === "baseline" ? "non-existent path comparison" : "authorized demo"}
                  maxHeight="max-h-[380px]"
                  tone="default"
                />
              </div>

              <div className="mt-3 flex items-start gap-2.5 rounded-[2px] border border-lilac/10 bg-white/[0.018] px-3.5 py-2.5">
                <Info className="mt-0.5 size-3.5 shrink-0 text-lilac/35" />
                <p className="text-[10.5px] leading-relaxed text-lilac/40">
                  {finding.evidence.note ??
                    "The observation is stored exactly as captured. Values that could contain live secrets are redacted in this demo record."}
                </p>
              </div>

              {finding.evidence.checks && finding.evidence.checks.length > 0 ? (
                <div className="mt-4">
                  <div className="flex items-center justify-between">
                    <p className="mono-label text-lilac/35">Observed checks</p>
                    <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                      {finding.evidence.checks.length} signals
                    </span>
                  </div>
                  <div className="mt-2 overflow-hidden rounded-[2px] border border-lilac/10">
                    {finding.evidence.checks.map((check, index) => {
                      const style = checkStateStyle[check.state];
                      const Icon = style.icon;
                      return (
                        <div
                          key={check.label}
                          className={classNames(
                            "grid grid-cols-[1fr_auto] items-start gap-3 px-3.5 py-3 sm:grid-cols-[1.1fr_1fr_1fr_auto]",
                            index > 0 ? "border-t border-lilac/[0.07]" : "",
                          )}
                        >
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[9px] text-lilac/25">
                              {String(index + 1).padStart(2, "0")}
                            </span>
                            <span className="text-[11px] text-lilac/65">{check.label}</span>
                          </div>
                          <div className="col-span-2 sm:col-span-1">
                            <p className="text-[10.5px] text-paper/80">{check.value}</p>
                            <p className="font-mono text-[8.5px] text-lilac/25">expected: {check.expected}</p>
                          </div>
                          <span className={classNames("inline-flex items-center gap-1 rounded-[3px] border px-1.5 py-0.5 text-[8.5px] font-mono uppercase tracking-[0.08em] sm:col-span-1", style.className)}>
                            <Icon className="size-2.5" />
                            {check.state}
                          </span>
                          <span />
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : null}

              {finding.evidence.comparison && finding.evidence.comparison.length > 0 ? (
                <div className="mt-4">
                  <div className="flex items-center justify-between">
                    <p className="mono-label text-lilac/35">Signal comparison</p>
                    <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                      baseline vs observed
                    </span>
                  </div>
                  <div className="mt-2 overflow-x-auto rounded-[2px] border border-lilac/10">
                    <table className="w-full min-w-[540px] border-collapse text-left">
                      <thead>
                        <tr className="border-b border-lilac/[0.07] bg-white/[0.015]">
                          <th className="px-3.5 py-2 font-mono text-[8px] font-normal uppercase tracking-[0.1em] text-lilac/25">Signal</th>
                          <th className="px-3.5 py-2 font-mono text-[8px] font-normal uppercase tracking-[0.1em] text-lilac/25">Baseline</th>
                          <th className="px-3.5 py-2 font-mono text-[8px] font-normal uppercase tracking-[0.1em] text-lilac/25">Observed</th>
                          <th className="px-3.5 py-2 font-mono text-[8px] font-normal uppercase tracking-[0.1em] text-lilac/25">Verdict</th>
                        </tr>
                      </thead>
                      <tbody>
                        {finding.evidence.comparison.map((row) => {
                          const style = verdictStyle[row.verdict];
                          const Icon = style.icon;
                          return (
                            <tr key={row.signal} className="border-b border-lilac/[0.05] last:border-0">
                              <td className="px-3.5 py-2.5 text-[10.5px] text-lilac/55">
                                {row.signal}
                                {row.note ? (
                                  <p className="mt-0.5 font-mono text-[8.5px] leading-relaxed text-lilac/25">{row.note}</p>
                                ) : null}
                              </td>
                              <td className="px-3.5 py-2.5 font-mono text-[10px] text-lilac/45">{row.baseline}</td>
                              <td className="px-3.5 py-2.5 font-mono text-[10px] text-paper/75">{row.observed}</td>
                              <td className={classNames("px-3.5 py-2.5 font-mono text-[8.5px] uppercase tracking-[0.08em]", style.className)}>
                                <span className="inline-flex items-center gap-1">
                                  <Icon className="size-3" /> {style.label}
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : null}
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-lilac/[0.08] bg-white/[0.012] px-5 py-2.5">
              <p className="flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                <TerminalSquare className="size-3" /> Evidence first · interpretation next
              </p>
              <p className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                {finding.sample ? "Sample capture · values redacted" : "Live capture"}
              </p>
            </div>
          </Panel>

          <Panel className="animate-fade-up delay-2 overflow-hidden">
            <PanelHeader
              eyebrow="02 / Interpretation"
              title="What it means, and how sure we are."
              description="The risk analysis is kept separate from the raw observation. Confidence describes the evidence, not the danger."
            />
            <div className="grid gap-0 border-b border-lilac/[0.08] lg:grid-cols-[1.25fr_0.75fr]">
              <div className="border-b border-lilac/[0.07] px-5 py-5 lg:border-b-0 lg:border-r">
                <div className="flex items-center gap-2">
                  <Target className="size-3.5 text-lavender/70" />
                  <p className="mono-label text-lilac/40">Impact</p>
                </div>
                <p className="mt-2.5 text-[12.5px] leading-relaxed text-lilac/65">{finding.impact}</p>
              </div>
              <div className="px-5 py-5">
                <p className="mono-label text-lilac/40">Risk framing</p>
                <div className="mt-3 space-y-3.5">
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[11px] text-lilac/45">Severity</span>
                      <SeverityBadge severity={finding.severity} compact />
                    </div>
                    <p className="mt-1.5 font-mono text-[9px] uppercase tracking-[0.08em] text-lilac/25">
                      {SEVERITY_LABEL[finding.severity]} impact potential
                    </p>
                  </div>
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[11px] text-lilac/45">Evidence strength</span>
                      <ConfidenceMeter confidence={finding.confidence} />
                    </div>
                    <p className="mt-1.5 font-mono text-[9px] uppercase tracking-[0.08em] text-lilac/25">
                      {CONFIDENCE_LABEL[finding.confidence]} confidence
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid gap-0 sm:grid-cols-2">
              <div className="border-b border-lilac/[0.07] px-5 py-5 sm:border-b-0 sm:border-r">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="size-3.5 text-high/80" />
                    <p className="mono-label text-lilac/40">Severity rationale</p>
                  </div>
                  <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-lilac/25">
                    Why {SEVERITY_LABEL[finding.severity]}
                  </span>
                </div>
                <p className="mt-2.5 text-[11.5px] leading-relaxed text-lilac/55">{finding.severityRationale}</p>
                <p className="mt-3 border-t border-lilac/[0.06] pt-2 font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                  Severity reflects potential impact and context
                </p>
              </div>
              <div className="px-5 py-5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Layers className="size-3.5 text-lavender/80" />
                    <p className="mono-label text-lilac/40">Confidence rationale</p>
                  </div>
                  <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-lilac/25">
                    Why {CONFIDENCE_LABEL[finding.confidence]}
                  </span>
                </div>
                <p className="mt-2.5 text-[11.5px] leading-relaxed text-lilac/55">{finding.confidenceRationale}</p>
                <p className="mt-3 border-t border-lilac/[0.06] pt-2 font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                  Confidence reflects evidence strength, not impact
                </p>
              </div>
            </div>
          </Panel>

          <Panel className="animate-fade-up delay-3 overflow-hidden">
            <PanelHeader
              eyebrow="03 / Remediation"
              title="What closes the finding."
              description="Specific, developer-applicable steps. A removed header alone is not the whole fix if the underlying cause is still reachable."
              action={<Wrench className="size-4 text-lilac/25" />}
            />
            <div className="px-5 py-5">
              <ol className="space-y-3">
                {finding.remediation.map((step, index) => (
                  <li key={step} className="flex gap-3">
                    <span className="flex size-5 shrink-0 items-center justify-center rounded-full border border-gold/25 bg-gold/[0.06] font-mono text-[9px] text-gold/80">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <p className="pt-0.5 text-[11.5px] leading-relaxed text-lilac/55">{step}</p>
                  </li>
                ))}
              </ol>

              {finding.fixSnippet ? (
                <div className="mt-5">
                  <div className="mb-2 flex items-center justify-between">
                    <p className="mono-label text-lilac/35">Suggested fix</p>
                    <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                      {finding.fixLanguage ?? "config"}
                    </span>
                  </div>
                  <CodeBlock
                    code={finding.fixSnippet}
                    title="Remediation snippet"
                    language={finding.fixLanguage}
                    maxHeight="max-h-[260px]"
                    showCopy
                  />
                </div>
              ) : null}

              <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-lilac/[0.07] pt-3.5">
                <span className="mono-label text-lilac/30">References</span>
                {finding.references.map((reference) => (
                  <span
                    key={reference.value}
                    className="inline-flex items-center gap-1.5 rounded-[3px] border border-lilac/10 bg-white/[0.02] px-2 py-1 text-[9.5px] text-lilac/40"
                  >
                    <span className="font-mono text-[8px] uppercase tracking-[0.06em] text-lilac/25">{reference.label}</span>
                    {reference.value}
                  </span>
                ))}
              </div>
            </div>
          </Panel>

          <Panel className="animate-fade-up delay-4 overflow-hidden">
            <PanelHeader
              eyebrow="04 / Verification"
              title="Before, after, and the rescan record."
              description="Resolving a finding requires the specific observed evidence to change, not just a second clean-looking response."
              action={
                <span
                  className={classNames(
                    "inline-flex items-center gap-1.5 rounded-[2px] border px-2 py-1 font-mono text-[8.5px] uppercase tracking-[0.1em]",
                    verificationTone === "good"
                      ? "border-good/25 bg-good/[0.06] text-good"
                      : verificationTone === "warn"
                        ? "border-gold/25 bg-gold/[0.06] text-gold"
                        : "border-lilac/15 bg-white/[0.02] text-lilac/40",
                  )}
                >
                  {verified ? <ShieldCheck className="size-3" /> : <Clock3 className="size-3" />}
                  {verificationLabel}
                </span>
              }
            />
            <div className="px-5 py-5">
              <div className="grid gap-3 lg:grid-cols-2">
                <div>
                  <div className="mb-1.5 flex items-center justify-between">
                    <p className="mono-label text-lilac/35">Before</p>
                    <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                      recorded at detection
                    </span>
                  </div>
                  <CodeBlock
                    code={verification.before}
                    title="Original observation"
                    tone="danger"
                    maxHeight="max-h-[180px]"
                    lineNumbers={false}
                    showCopy={false}
                  />
                </div>
                <div>
                  <div className="mb-1.5 flex items-center justify-between">
                    <p className="mono-label text-lilac/35">After</p>
                    <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                      {verification.checkedAt ? formatDate(verification.checkedAt) : "not rescanned"}
                    </span>
                  </div>
                  {verification.after ? (
                    <CodeBlock
                      code={verification.after}
                      title="Verification observation"
                      tone="good"
                      maxHeight="max-h-[180px]"
                      lineNumbers={false}
                      showCopy={false}
                    />
                  ) : (
                    <div className="flex h-[132px] flex-col items-center justify-center rounded-[3px] border border-dashed border-lilac/15 bg-white/[0.012] px-4 text-center">
                      <Clock3 className="size-4 text-lilac/25" />
                      <p className="mt-2 text-[11px] text-lilac/45">No verification observation yet.</p>
                      <p className="mt-0.5 text-[9.5px] text-lilac/25">
                        Run the rescan to record a before-and-after comparison.
                      </p>
                    </div>
                  )}
                </div>
              </div>

              <div className="mt-4 flex flex-wrap items-start justify-between gap-3 rounded-[2px] border border-lilac/10 bg-white/[0.018] px-3.5 py-3">
                <div className="flex min-w-0 items-start gap-2.5">
                  {verified ? (
                    verification.status === "verified-resolved" ? (
                      <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-good" />
                    ) : (
                      <CircleAlert className="mt-0.5 size-3.5 shrink-0 text-gold" />
                    )
                  ) : (
                    <Info className="mt-0.5 size-3.5 shrink-0 text-lilac/35" />
                  )}
                  <div>
                    <p className="text-[11px] leading-relaxed text-lilac/55">
                      {verification.note ??
                        "A rescan re-checks only this finding's evidence and records the change."}
                    </p>
                    <div className="mt-1.5 flex flex-wrap items-center gap-2 font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                      <span>{verified ? "Verification recorded" : "Original evidence only"}</span>
                      {verification.checkedAt ? (
                        <>
                          <span className="size-[2px] rounded-full bg-lilac/20" />
                          <span>{formatDateTime(verification.checkedAt)}</span>
                        </>
                      ) : null}
                      {verification.scanId ? (
                        <>
                          <span className="size-[2px] rounded-full bg-lilac/20" />
                          <Link to={`/scans/${verification.scanId}/progress`} className="text-lavender/60 hover:text-paper">
                            view verification run
                          </Link>
                        </>
                      ) : null}
                    </div>
                  </div>
                </div>
                <Button variant="secondary" size="sm" icon={RefreshCw} onClick={() => setRescanOpen(true)}>
                  {finding.verification.status === "not-verified" ? "Verify finding" : "Rescan again"}
                </Button>
              </div>

              <p className="mt-3 flex items-start gap-1.5 font-mono text-[8.5px] leading-relaxed text-lilac/25">
                <LockKeyhole className="mt-0.5 size-3 shrink-0" />
                Demo verification is scripted sample data. A resolved marker only means the recorded
                observation changed; it is not a guarantee that the entire application is secure.
              </p>
            </div>
          </Panel>
        </div>

        <aside className="space-y-4 xl:sticky xl:top-[78px] xl:self-start">
          <Panel raised className="animate-fade-up overflow-hidden">
            <div className="border-b border-lilac/[0.08] px-4 py-3.5">
              <p className="mono-label text-lilac/35">Finding record</p>
              <p className="mt-1.5 font-mono text-[12px] text-paper/85">{finding.id}</p>
              <p className="mt-0.5 font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
                {finding.sample ? "Sample data · demo workspace" : "Live evidence"}
              </p>
            </div>
            <div className="space-y-3 px-4 py-4">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10.5px] text-lilac/35">Status</span>
                <StatusBadge status={finding.status} />
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10.5px] text-lilac/35">Module</span>
                <span className="text-right text-[10.5px] text-lilac/60">{finding.moduleName}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10.5px] text-lilac/35">Rescans</span>
                <span className="font-mono text-[10.5px] text-lilac/60">{finding.rescanCount}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10.5px] text-lilac/35">Detected</span>
                <span className="text-[10.5px] text-lilac/60">{formatRelative(finding.detectedAt)}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10.5px] text-lilac/35">Category</span>
                <span className="text-[10.5px] text-lilac/60">{finding.categoryLabel}</span>
              </div>
              <div className="border-t border-lilac/[0.07] pt-3">
                <p className="text-[10.5px] leading-relaxed text-lilac/30">
                  Fingerprint{" "}
                  <span className="font-mono text-[9.5px] text-lilac/50">{finding.fingerprint}</span>
                </p>
              </div>
            </div>
            <div className="border-t border-lilac/[0.08] px-4 py-3">
              <Button variant="gold" size="sm" icon={RefreshCw} className="w-full" onClick={() => setRescanOpen(true)}>
                Rescan this finding
              </Button>
              {sourceScan ? (
                <Link
                  to={`/reports/${sourceScan.id}`}
                  className="mt-2 flex h-8 w-full items-center justify-center gap-1.5 rounded-[2px] border border-lilac/12 text-[10.5px] text-lilac/50 transition hover:border-lilac/25 hover:text-paper"
                >
                  <FileText className="size-3" /> Open scan report
                </Link>
              ) : null}
            </div>
          </Panel>

          {related.length > 0 ? (
            <Panel className="animate-fade-up delay-1 overflow-hidden">
              <div className="border-b border-lilac/[0.08] px-4 py-3.5">
                <p className="mono-label text-lilac/35">Same module</p>
                <p className="mt-1 text-[10px] text-lilac/30">
                  Other {finding.categoryLabel.toLowerCase()} findings from this scan.
                </p>
              </div>
              <div className="divide-y divide-lilac/[0.06]">
                {related.map((item) => (
                  <Link
                    key={item.id}
                    to={`/findings/${item.id}`}
                    className="group flex items-start gap-2.5 px-4 py-3 transition hover:bg-white/[0.025]"
                  >
                    <SeverityBadge severity={item.severity} compact className="mt-0.5 shrink-0" />
                    <div className="min-w-0 flex-1">
                      <p className="line-clamp-2 text-[10.5px] leading-snug text-lilac/60 transition group-hover:text-paper">
                        {item.title}
                      </p>
                      <p className="mt-1 font-mono text-[8.5px] text-lilac/25">{item.id}</p>
                    </div>
                    <ChevronRight className="mt-0.5 size-3 shrink-0 text-lilac/20 group-hover:text-lilac/50" />
                  </Link>
                ))}
              </div>
              <div className="border-t border-lilac/[0.08] px-4 py-2.5">
                <Link to={`/findings?scan=${finding.scanId}`} className="text-[10px] text-lilac/40 transition hover:text-paper">
                  View all findings <ArrowRight className="ml-1 inline size-3" />
                </Link>
              </div>
            </Panel>
          ) : null}

          <div className="animate-fade-up delay-2 rounded-[3px] border border-cyan/15 bg-cyan/[0.03] p-4">
            <div className="flex items-center gap-2">
              <Sparkles className="size-3.5 text-cyan/70" />
              <p className="mono-label text-cyan/75">{finding.sample ? "Sample record" : "Live evidence"}</p>
            </div>
            <p className="mt-2 text-[10px] leading-relaxed text-lilac/40">
              {finding.sample
                ? "This record is marked as illustrative sample data."
                : "This finding was captured from an authorized target scan and persisted in SQLite."}
            </p>
          </div>
        </aside>
      </div>

      <RescanModal
        finding={finding}
        open={rescanOpen}
        onClose={() => setRescanOpen(false)}
        onConfirm={startRescan}
      />
    </div>
  );
}
