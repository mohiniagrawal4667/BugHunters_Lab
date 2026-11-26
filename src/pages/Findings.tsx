import { Fragment, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  ArrowRight,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  FileSearch,
  FileText,
  Filter,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ServerOff,
  X,
} from "lucide-react";
import { useWorkspace } from "../store/WorkspaceStore";
import { PageHeader } from "../components/ui/PageHeader";
import { Button, ButtonLink } from "../components/ui/Button";
import {
  ConfidenceMeter,
  DemoBadge,
  SeverityBadge,
  StatusBadge,
} from "../components/ui/Badges";
import { CodeBlock } from "../components/ui/CodeBlock";
import {
  SeverityStrip,
  countSeverities,
} from "../components/ui/SeverityDistribution";
import { EmptyState } from "../components/ui/EmptyState";
import { Panel, SectionLabel } from "../components/ui/Section";
import { CHECK_ORDER } from "../data/checks";
import {
  CATEGORY_LABEL,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  STATUS_LABEL,
  classNames,
  confidenceRank,
  formatDate,
  formatDateTime,
  formatRelative,
  hostnameOf,
  pluralize,
  severityRank,
  statusRank,
} from "../lib/format";
import type { CheckId, CheckStatus, Finding, FindingStatus, Severity } from "../types";

type SortKey = "severity" | "confidence" | "recent";

const checkStatusLabel: Record<CheckStatus, { label: string; className: string }> = {
  finding_detected: { label: "Finding detected", className: "border-gold/30 bg-gold/[0.08] text-gold" },
  no_issue_observed: { label: "No issue observed", className: "border-good/30 bg-good/[0.08] text-good" },
  inconclusive: { label: "Inconclusive", className: "border-medium/30 bg-medium/[0.08] text-medium" },
  not_applicable: { label: "Not applicable", className: "border-lilac/20 bg-white/[0.04] text-lilac/65" },
  scan_failed: { label: "Scan failed", className: "border-critical/35 bg-critical/[0.09] text-critical" },
};

function SelectShell({
  id,
  value,
  onChange,
  label,
  children,
  className,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={classNames("relative", className)}>
      <label htmlFor={id} className="sr-only">
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-9 w-full cursor-pointer appearance-none rounded-[2px] border border-lilac/12 bg-[#07101d] pl-3 pr-8 text-[11px] text-lilac/70 outline-none transition hover:border-lilac/25 focus:border-cyan/50"
      >
        {children}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 size-3 -translate-y-1/2 text-lilac/30" />
    </div>
  );
}

const severityRail: Record<Severity, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  informational: "bg-lilac/40",
};

function FindingRow({
  finding,
  expanded,
  onToggleExpand,
}: {
  finding: Finding;
  expanded: boolean;
  onToggleExpand: () => void;
}) {
  return (
    <Fragment>
      <tr className="group border-b border-[#142338] transition hover:bg-cyan/[0.018]">
        <td className="py-3.5 pl-5 pr-4">
          <div className="flex gap-3">
            <span className={classNames("w-[2px] shrink-0 self-stretch opacity-70", severityRail[finding.severity])} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/40">
                  {finding.id}
                </span>
                <span className="font-mono text-[8px] text-cyan/65">{finding.moduleName}</span>
              </div>
              <Link to={`/findings/${finding.id}`} className="mt-0.5 block max-w-[440px] truncate text-[12.5px] font-medium text-paper/90 transition hover:text-cyan">
                {finding.title}
              </Link>
              <p className="mt-1 max-w-[460px] truncate font-mono text-[9px] text-lilac/45">
                {finding.targetUrl ?? finding.targetPath}
              </p>
              <p className="mt-1 max-w-[480px] line-clamp-2 text-[10.5px] text-lilac/55">
                {finding.summary}
              </p>
            </div>
          </div>
        </td>
        <td className="px-4 py-3.5">
          <span className="text-[11px] text-lilac/60">{finding.categoryLabel}</span>
        </td>
        <td className="px-4 py-3.5">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="px-4 py-3.5">
          <div className="flex flex-col gap-1">
            <ConfidenceMeter confidence={finding.confidence} />
            <span className="font-mono text-[8px] uppercase tracking-[0.08em] text-lilac/25">
              {finding.confidence} confidence
            </span>
          </div>
        </td>
        <td className="px-4 py-3.5">
          <StatusBadge status={finding.status} />
        </td>
        <td className="px-4 py-3.5">
          <p className="text-[10.5px] text-lilac/50">{formatDate(finding.detectedAt)}</p>
          <p className="mt-0.5 font-mono text-[8px] text-lilac/25">{formatRelative(finding.detectedAt)}</p>
        </td>
        <td className="py-3.5 pl-2 pr-5 text-right">
          <div className="flex items-center justify-end gap-1.5">
            <button
              type="button"
              onClick={onToggleExpand}
              className="inline-flex h-7 items-center gap-1 rounded-[2px] border border-cyan/20 px-2 font-mono text-[8px] uppercase tracking-[0.08em] text-cyan/80 transition hover:border-cyan/45 hover:text-cyan"
            >
              {expanded ? "Hide" : "Evidence"}
              {expanded ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />}
            </button>
            <Link
              to={`/findings/${finding.id}`}
              aria-label={`Open finding ${finding.title}`}
              className="inline-flex size-7 items-center justify-center rounded-[2px] text-lilac/25 transition hover:bg-white/[0.05] hover:text-paper group-hover:text-lilac/60"
            >
              <ChevronRight className="size-4" />
            </Link>
          </div>
        </td>
      </tr>
      {expanded ? (
        <tr className="border-b border-[#142338] bg-[#040912]">
          <td colSpan={7} className="px-5 py-4">
            <div className="grid gap-4 lg:grid-cols-2">
              <CodeBlock
                title="Observed response"
                code={finding.evidence.response}
                language="http"
                maxHeight="max-h-[220px]"
              />
              <CodeBlock
                title={finding.evidence.baseline ? "Baseline comparison" : "Scanner request"}
                code={finding.evidence.baseline ?? finding.evidence.request}
                language="http"
                maxHeight="max-h-[220px]"
              />
            </div>
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[10.5px] text-lilac/55">
              <span>Remediation: {finding.remediation[0] ?? "Review finding details."}</span>
              <Link to={`/findings/${finding.id}`} className="font-mono text-[9px] uppercase tracking-[0.1em] text-cyan hover:underline">
                Open full case file →
              </Link>
            </div>
          </td>
        </tr>
      ) : null}
    </Fragment>
  );
}

export function Findings() {
  const { scans, findings, getFindingsForScan, latestPrimaryScan, loading, backendError, refreshWorkspace } =
    useWorkspace();
  const [searchParams] = useSearchParams();
  const orderedScans = useMemo(
    () =>
      [...scans]
        .filter((scan) => !scan.rescanOfFindingId)
        .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()),
    [scans],
  );

  const [scanId, setScanId] = useState<string>(
    () => searchParams.get("scan") ?? latestPrimaryScan?.id ?? orderedScans[0]?.id ?? "all",
  );
  const [severities, setSeverities] = useState<Severity[]>([]);
  const [category, setCategory] = useState<"all" | CheckId>("all");
  const [status, setStatus] = useState<"all" | FindingStatus>("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortKey>("severity");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    const requested = searchParams.get("scan");
    if (requested && scans.some((scan) => scan.id === requested)) {
      setScanId(requested);
    } else if (scanId !== "all" && !scans.some((scan) => scan.id === scanId)) {
      setScanId(latestPrimaryScan?.id ?? orderedScans[0]?.id ?? "all");
    }
  }, [latestPrimaryScan?.id, orderedScans, scanId, scans, searchParams]);

  const selectedScan = scanId === "all" ? undefined : scans.find((scan) => scan.id === scanId);
  const activeScans = selectedScan ? [selectedScan] : orderedScans;
  const scanFindings = selectedScan ? getFindingsForScan(selectedScan.id) : findings;
  const counts = countSeverities(scanFindings);
  const categoryCounts = CHECK_ORDER.reduce<Record<CheckId, number>>(
    (acc, id) => {
      acc[id] = scanFindings.filter((finding) => finding.category === id).length;
      return acc;
    },
    { headers: 0, cookies: 0, paths: 0, injection: 0 },
  );
  const openCount = scanFindings.filter((finding) => finding.status === "open").length;
  const pendingCount = scanFindings.filter((finding) => finding.status === "pending").length;
  const resolvedCount = scanFindings.filter((finding) => finding.status === "resolved").length;

  const moduleObservations = useMemo(() => {
    const rows: Array<{
      id: string;
      scanId: string;
      target: string;
      moduleName: string;
      status: CheckStatus;
      summary: string;
      findingsCount: number;
      timestamp: string;
      error?: string | null;
    }> = [];
    for (const scan of activeScans) {
      const results = scan.checkResults ?? {};
      for (const check of scan.checks) {
        const res = results[check];
        if (!res) continue;
        rows.push({
          id: `${scan.id}-${check}`,
          scanId: scan.id,
          target: scan.target,
          moduleName: res.moduleName,
          status: res.status,
          summary: res.summary,
          findingsCount: res.findingsCount,
          timestamp: scan.completedAt ?? scan.startedAt,
          error: res.error,
        });
      }
    }
    return rows;
  }, [activeScans]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const list = scanFindings.filter((finding) => {
      if (severities.length > 0 && !severities.includes(finding.severity)) return false;
      if (category !== "all" && finding.category !== category) return false;
      if (status !== "all" && finding.status !== status) return false;
      if (
        needle &&
        !finding.title.toLowerCase().includes(needle) &&
        !finding.targetPath.toLowerCase().includes(needle) &&
        !(finding.targetUrl ?? "").toLowerCase().includes(needle) &&
        !finding.categoryLabel.toLowerCase().includes(needle) &&
        !finding.id.toLowerCase().includes(needle)
      ) {
        return false;
      }
      return true;
    });
    return [...list].sort((a, b) => {
      if (sort === "recent") {
        return new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime();
      }
      if (sort === "confidence") {
        return (
          confidenceRank(a.confidence) - confidenceRank(b.confidence) ||
          severityRank(a.severity) - severityRank(b.severity)
        );
      }
      return (
        severityRank(a.severity) - severityRank(b.severity) ||
        confidenceRank(a.confidence) - confidenceRank(b.confidence) ||
        statusRank(a.status) - statusRank(b.status)
      );
    });
  }, [category, query, scanFindings, severities, sort, status]);

  const activeFilterCount =
    severities.length + (category !== "all" ? 1 : 0) + (status !== "all" ? 1 : 0) + (query ? 1 : 0);

  function toggleSeverity(severity: Severity) {
    setSeverities((current) =>
      current.includes(severity)
        ? current.filter((item) => item !== severity)
        : [...current, severity],
    );
  }

  function clearFilters() {
    setSeverities([]);
    setCategory("all");
    setStatus("all");
    setQuery("");
  }

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Evidence log / SQLite records"
        title="Every observation, with the evidence."
        description="Inspect real findings and module-level observations collected from authorized scans. Expand any row to inspect captured HTTP responses and baselines."
        actions={
          <>
            <Button variant="secondary" size="md" icon={RefreshCw} loading={loading} onClick={() => void refreshWorkspace()}>
              Refresh
            </Button>
            {selectedScan ? (
              <ButtonLink to={`/reports/${selectedScan.id}`} variant="secondary" size="md" icon={FileText}>
                Open report
              </ButtonLink>
            ) : null}
            <ButtonLink to="/scan/new" variant="gold" size="md" icon={Plus}>
              New investigation
            </ButtonLink>
          </>
        }
      />

      <Panel className="animate-fade-up overflow-hidden">
        <div className="flex flex-col gap-4 border-b border-[#1a2b42] bg-[#08111e]/50 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-wrap items-center gap-3">
            <div>
              <SectionLabel>Scope filter / persisted scans</SectionLabel>
              <div className="mt-1.5 flex items-center gap-2">
                <SelectShell
                  id="scan-select"
                  label="Select scan record"
                  value={selectedScan?.id ?? "all"}
                  onChange={setScanId}
                  className="min-w-[240px]"
                >
                  <option value="all">All persisted scans ({orderedScans.length})</option>
                  {orderedScans.map((scan) => (
                    <option key={scan.id} value={scan.id}>
                      {scan.label} · {hostnameOf(scan.target)} · {formatDate(scan.startedAt)} ({scan.status})
                    </option>
                  ))}
                </SelectShell>
                {selectedScan?.dataSource === "sample" ? <DemoBadge label="Sample data" subtle /> : null}
              </div>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-[10px] text-lilac/35">
            <span className="size-[5px] rounded-full bg-critical" /> {openCount} open
            <span className="ml-1 size-[5px] rounded-full bg-gold" /> {pendingCount} pending
            <span className="ml-1 size-[5px] rounded-full bg-good" /> {resolvedCount} resolved
          </div>
        </div>

        <div className="grid grid-cols-2 divide-x divide-y divide-lilac/[0.07] border-b border-lilac/[0.08] sm:grid-cols-4 lg:grid-cols-7 sm:divide-y-0">
          <div className="px-4 py-3">
            <p className="mono-label text-lilac/30">Total</p>
            <p className="mt-1.5 font-display text-[26px] font-medium leading-none tracking-[-0.03em] text-paper">
              {scanFindings.length}
            </p>
          </div>
          {SEVERITY_ORDER.map((severity) => (
            <div key={severity} className="px-4 py-3">
              <p className="mono-label flex items-center gap-1.5 text-lilac/30">
                <span className={classNames("size-[5px] rounded-full", severityRail[severity])} />
                {SEVERITY_LABEL[severity]}
              </p>
              <p
                className={classNames(
                  "mt-1.5 font-display text-[26px] font-medium leading-none tracking-[-0.03em]",
                  severity === "critical"
                    ? "text-critical"
                    : severity === "high"
                      ? "text-high"
                      : severity === "medium"
                        ? "text-medium"
                        : severity === "low"
                          ? "text-low"
                          : "text-lilac/70",
                )}
              >
                {counts[severity]}
              </p>
            </div>
          ))}
          <div className="px-4 py-3">
            <p className="mono-label text-lilac/30">Resolved</p>
            <p className="mt-1.5 font-display text-[26px] font-medium leading-none tracking-[-0.03em] text-good">
              {resolvedCount}
            </p>
          </div>
        </div>

        <div className="border-b border-lilac/[0.08] px-5 py-4">
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
              <div className="relative min-w-0 flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-lilac/30" />
                <input
                  type="search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search findings, targets or evidence IDs..."
                  className="h-9 w-full rounded-[2px] border border-lilac/12 bg-[#07101d] pl-9 pr-8 text-[11px] text-paper outline-none transition placeholder:text-lilac/25 hover:border-lilac/25 focus:border-cyan/50"
                  aria-label="Search findings"
                />
                {query ? (
                  <button
                    type="button"
                    onClick={() => setQuery("")}
                    aria-label="Clear search"
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-lilac/30 hover:text-lilac/70"
                  >
                    <X className="size-3" />
                  </button>
                ) : null}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <div className="flex flex-wrap items-center gap-1 overflow-hidden rounded-[2px] border border-lilac/12 p-0.5">
                  {SEVERITY_ORDER.map((severity) => {
                    const active = severities.includes(severity);
                    return (
                      <button
                        key={severity}
                        type="button"
                        aria-pressed={active}
                        onClick={() => toggleSeverity(severity)}
                        className={classNames(
                          "flex h-7 items-center gap-1.5 rounded-[3px] px-2 text-[9.5px] uppercase tracking-[0.06em] transition",
                          active
                            ? "bg-cyan/[0.12] text-paper"
                            : "text-lilac/40 hover:bg-white/[0.04] hover:text-lilac/70",
                        )}
                      >
                        <span className={classNames("size-[4px] rounded-full", severityRail[severity])} />
                        {severity === "informational" ? "Info" : SEVERITY_LABEL[severity]}
                        <span className="font-mono text-[8.5px] opacity-60">{counts[severity]}</span>
                      </button>
                    );
                  })}
                </div>

                <SelectShell id="category-select" label="Filter by category" value={category} onChange={(value) => setCategory(value as "all" | CheckId)} className="w-[150px]">
                  <option value="all">All categories</option>
                  {CHECK_ORDER.map((id) => (
                    <option key={id} value={id}>
                      {CATEGORY_LABEL[id]} ({categoryCounts[id]})
                    </option>
                  ))}
                </SelectShell>

                <SelectShell id="status-select" label="Filter by status" value={status} onChange={(value) => setStatus(value as "all" | FindingStatus)} className="w-[140px]">
                  <option value="all">All statuses</option>
                  {(["open", "pending", "resolved"] as FindingStatus[]).map((value) => (
                    <option key={value} value={value}>
                      {STATUS_LABEL[value]}
                    </option>
                  ))}
                </SelectShell>

                <SelectShell id="sort-select" label="Sort findings" value={sort} onChange={(value) => setSort(value as SortKey)} className="w-[130px]">
                  <option value="severity">Severity first</option>
                  <option value="confidence">Confidence first</option>
                  <option value="recent">Most recent</option>
                </SelectShell>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-[10px] text-lilac/35">
                <Filter className="size-3" />
                <span>
                  Showing <span className="font-mono text-lilac/70">{filtered.length}</span> of{" "}
                  <span className="font-mono text-lilac/70">{scanFindings.length}</span>{" "}
                  {pluralize(scanFindings.length, "finding")}
                </span>
                {activeFilterCount > 0 ? (
                  <button
                    type="button"
                    onClick={clearFilters}
                    className="ml-1 inline-flex items-center gap-1 rounded-[3px] border border-lilac/12 px-1.5 py-0.5 text-[9.5px] text-lilac/45 transition hover:border-lilac/25 hover:text-paper"
                  >
                    <RotateCcw className="size-2.5" /> Clear {activeFilterCount}
                  </button>
                ) : null}
              </div>
              <SeverityStrip counts={counts} className="w-28" />
            </div>
          </div>
        </div>

        {backendError ? (
          <EmptyState
            icon={ServerOff}
            title="Cannot load evidence from backend."
            description={backendError}
            action={
              <Button variant="secondary" size="sm" icon={RefreshCw} onClick={() => void refreshWorkspace()}>
                Retry
              </Button>
            }
          />
        ) : orderedScans.length === 0 ? (
          <EmptyState
            icon={FileSearch}
            title="No real scan records yet."
            description="Validate an authorized target and run an investigation to record observations and findings in SQLite."
            action={
              <ButtonLink to="/scan/new" variant="gold" size="md" icon={Plus}>
                New investigation
              </ButtonLink>
            }
          />
        ) : scanFindings.length === 0 ? (
          <EmptyState
            icon={FileSearch}
            title="No findings recorded for this selection."
            description="Inspect the module observations below to view what each scanner checked and observed."
          />
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={FileSearch}
            title="No findings match these filters."
            description="Adjust the severity, category or status filters, or clear the search to review all records."
            action={
              <button
                type="button"
                onClick={clearFilters}
                className="inline-flex h-8 items-center gap-1.5 rounded-[2px] border border-lilac/15 px-3 text-[11px] text-lilac/65 transition hover:border-lilac/30 hover:text-paper"
              >
                <RotateCcw className="size-3" /> Clear filters
              </button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[940px] border-collapse text-left">
              <thead>
                <tr className="border-b border-[#1a2b42] bg-[#060d18]">
                  <th className="py-2.5 pl-5 pr-4 font-mono text-[8.5px] font-normal uppercase tracking-[0.12em] text-lilac/30">
                    Evidence ID / Module / Observation
                  </th>
                  <th className="px-4 py-2.5 font-mono text-[8.5px] font-normal uppercase tracking-[0.12em] text-lilac/30">
                    Category
                  </th>
                  <th className="px-4 py-2.5 font-mono text-[8.5px] font-normal uppercase tracking-[0.12em] text-lilac/30">
                    Severity
                  </th>
                  <th className="px-4 py-2.5 font-mono text-[8.5px] font-normal uppercase tracking-[0.12em] text-lilac/30">
                    Confidence
                  </th>
                  <th className="px-4 py-2.5 font-mono text-[8.5px] font-normal uppercase tracking-[0.12em] text-lilac/30">
                    Status
                  </th>
                  <th className="px-4 py-2.5 font-mono text-[8.5px] font-normal uppercase tracking-[0.12em] text-lilac/30">
                    Timestamp
                  </th>
                  <th className="w-28 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {filtered.map((finding) => (
                  <FindingRow
                    key={finding.id}
                    finding={finding}
                    expanded={expandedId === finding.id}
                    onToggleExpand={() =>
                      setExpandedId((curr) => (curr === finding.id ? null : finding.id))
                    }
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-lilac/[0.08] px-5 py-3">
          <p className="flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
            <ArrowRight className="size-3" /> SQLite live evidence records
          </p>
          <p className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
            {selectedScan ? `${selectedScan.label} · ${selectedScan.id}` : `${orderedScans.length} scan(s)`}
          </p>
        </div>
      </Panel>

      {/* Module-level observations (always shown even when 0 vulnerabilities are found) */}
      {moduleObservations.length > 0 ? (
        <Panel className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-[#1a2b42] bg-[#08111e]/50 px-5 py-3.5">
            <div>
              <SectionLabel>Module observations</SectionLabel>
              <p className="mt-1 text-[11.5px] text-lilac/55">
                All executed scanner checks, including clean (`No issue observed`), `Not applicable`, `Inconclusive`, and `Scan failed` outcomes.
              </p>
            </div>
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-lilac/35">
              {moduleObservations.length} records
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] border-collapse text-left">
              <thead>
                <tr className="border-b border-[#1a2b42] bg-[#060d18]">
                  <th className="px-4 py-2.5 font-mono text-[8px] font-normal uppercase tracking-[0.1em] text-lilac/30">Evidence ID</th>
                  <th className="px-4 py-2.5 font-mono text-[8px] font-normal uppercase tracking-[0.1em] text-lilac/30">Target</th>
                  <th className="px-4 py-2.5 font-mono text-[8px] font-normal uppercase tracking-[0.1em] text-lilac/30">Scanner module</th>
                  <th className="px-4 py-2.5 font-mono text-[8px] font-normal uppercase tracking-[0.1em] text-lilac/30">Observation</th>
                  <th className="px-4 py-2.5 font-mono text-[8px] font-normal uppercase tracking-[0.1em] text-lilac/30">Status</th>
                  <th className="px-4 py-2.5 font-mono text-[8px] font-normal uppercase tracking-[0.1em] text-lilac/30">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {moduleObservations.map((row) => {
                  const st = checkStatusLabel[row.status];
                  return (
                    <tr key={row.id} className="border-b border-[#142338] last:border-0 hover:bg-white/[0.015]">
                      <td className="px-4 py-3 font-mono text-[9px] text-lilac/50">
                        <Link to={`/scans/${row.scanId}/progress`} className="hover:text-cyan">
                          {row.id}
                        </Link>
                      </td>
                      <td className="max-w-[200px] truncate px-4 py-3 font-mono text-[10px] text-paper/80" title={row.target}>
                        {row.target}
                      </td>
                      <td className="px-4 py-3 text-[11px] text-lilac/70">{row.moduleName}</td>
                      <td className="max-w-[360px] px-4 py-3 text-[11px] text-lilac/60">
                        {row.summary}
                        {row.error ? <p className="mt-0.5 text-[10px] text-critical">{row.error}</p> : null}
                      </td>
                      <td className="px-4 py-3">
                        <span className={classNames("inline-flex rounded-[2px] border px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-[0.08em]", st.className)}>
                          {st.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-[9.5px] text-lilac/45">
                        {formatDateTime(row.timestamp)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}
    </div>
  );
}
