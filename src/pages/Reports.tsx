import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ArrowRight,
  ChevronRight,
  FileDown,
  History,
  LoaderCircle,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ServerOff,
  ShieldCheck,
} from "lucide-react";
import { useWorkspace } from "../store/WorkspaceStore";
import { useReportExport } from "../hooks/useReportExport";
import { PageHeader } from "../components/ui/PageHeader";
import { Button, ButtonLink } from "../components/ui/Button";
import { SeverityStrip, countSeverities } from "../components/ui/SeverityDistribution";
import { EmptyState } from "../components/ui/EmptyState";
import { Panel, SectionLabel } from "../components/ui/Section";
import {
  classNames,
  formatDate,
  formatDateTime,
  formatDuration,
  formatRelative,
  hostnameOf,
  pluralize,
} from "../lib/format";
import type { Scan } from "../types";

type ReportFilter = "all" | "completed" | "failed" | "cancelled";

const statusStyle: Record<Scan["status"], { label: string; className: string }> = {
  completed: { label: "Completed", className: "border-good/25 bg-good/[0.06] text-good" },
  running: { label: "Running", className: "border-gold/30 bg-gold/[0.07] text-gold" },
  failed: { label: "Failed", className: "border-critical/25 bg-critical/[0.06] text-critical" },
  cancelled: { label: "Stopped", className: "border-lilac/15 bg-white/[0.03] text-lilac/45" },
};

function StatusPill({ scan }: { scan: Scan }) {
  const style = statusStyle[scan.status];
  return (
    <span className={classNames("inline-flex items-center gap-1.5 whitespace-nowrap rounded-[2px] border px-1.5 py-0.5 font-mono text-[8.5px] uppercase tracking-[0.08em]", style.className)}>
      <span className="size-[4px] rounded-full bg-current" />
      {style.label}
    </span>
  );
}

export function Reports() {
  const navigate = useNavigate();
  const { scans, getFindingsForScan, getFinding, loading, backendError, refreshWorkspace } = useWorkspace();
  const { exportReport, exportingId } = useReportExport();
  const [filter, setFilter] = useState<ReportFilter>("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    void refreshWorkspace();
  }, [refreshWorkspace]);

  const ordered = useMemo(
    () => [...scans].sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()),
    [scans],
  );

  const completedCount = scans.filter((scan) => scan.status === "completed").length;
  const failedCount = scans.filter((scan) => scan.status === "failed").length;
  const stoppedCount = scans.filter((scan) => scan.status === "cancelled").length;
  const totalEvidence = scans
    .filter((scan) => scan.status === "completed")
    .reduce((total, scan) => total + getFindingsForScan(scan.id).length, 0);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return ordered.filter((scan) => {
      if (filter !== "all" && scan.status !== filter) return false;
      if (
        needle &&
        !scan.label.toLowerCase().includes(needle) &&
        !scan.id.toLowerCase().includes(needle) &&
        !scan.target.toLowerCase().includes(needle) &&
        !scan.checks.join(" ").includes(needle)
      ) {
        return false;
      }
      return true;
    });
  }, [filter, ordered, query]);

  function openScan(scan: Scan) {
    return navigate(`/scans/${scan.id}/progress`);
  }

  return (
    <div>
      <PageHeader
        eyebrow="Case records / database history"
        title="Every run leaves a record."
        description="Review real scan records persisted in the backend SQLite database, inspect their execution logs and findings, and export PDF reports."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="secondary"
              size="md"
              icon={RefreshCw}
              loading={loading}
              onClick={() => void refreshWorkspace()}
            >
              Refresh
            </Button>
            <ButtonLink to="/scan/new" variant="gold" size="md" icon={Plus}>
              New investigation
            </ButtonLink>
          </div>
        }
      />

      <div className="grid grid-cols-2 divide-x divide-y divide-[#1a2b42] overflow-hidden rounded-[2px] border border-[#1a2b42] bg-[#07101d]/75 sm:grid-cols-4 sm:divide-y-0">
        <div className="px-4 py-3.5">
          <p className="mono-label text-lilac/30">All runs</p>
          <p className="mt-1.5 font-display text-[30px] font-medium leading-none tracking-[-0.04em] text-paper">{scans.length}</p>
          <p className="mt-1 text-[9.5px] text-lilac/25">SQLite database records</p>
        </div>
        <div className="px-4 py-3.5">
          <p className="mono-label flex items-center gap-1.5 text-lilac/30">
            <span className="size-[4px] rounded-full bg-good" /> Completed
          </p>
          <p className="mt-1.5 font-display text-[30px] font-medium leading-none tracking-[-0.04em] text-paper">{completedCount}</p>
          <p className="mt-1 text-[9.5px] text-lilac/25">Persisted completed scans</p>
        </div>
        <div className="px-4 py-3.5">
          <p className="mono-label flex items-center gap-1.5 text-lilac/30">
            <span className="size-[4px] rounded-full bg-critical" /> Failed / stopped
          </p>
          <p className="mt-1.5 font-display text-[30px] font-medium leading-none tracking-[-0.04em] text-paper">
            {failedCount + stoppedCount}
          </p>
          <p className="mt-1 text-[9.5px] text-lilac/25">Recorded failures</p>
        </div>
        <div className="px-4 py-3.5">
          <p className="mono-label flex items-center gap-1.5 text-lilac/30">
            <span className="size-[4px] rounded-full bg-lavender" /> Evidence records
          </p>
          <p className="mt-1.5 font-display text-[30px] font-medium leading-none tracking-[-0.04em] text-paper">{totalEvidence}</p>
          <p className="mt-1 text-[9.5px] text-lilac/25">Real findings across runs</p>
        </div>
      </div>

      <Panel className="animate-fade-up mt-5 overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-[#1a2b42] bg-[#08111e]/50 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <SectionLabel>History</SectionLabel>
            <div className="mt-1.5 flex flex-wrap items-center gap-2">
              <h2 className="font-display text-[18px] font-medium tracking-[-0.02em] text-paper">Scan ledger</h2>
              <span className="inline-flex items-center gap-1.5 rounded-[2px] border border-cyan/25 bg-cyan/[0.05] px-2 py-0.5 font-mono text-[8.5px] uppercase tracking-[0.12em] text-cyan">
                <span className="size-[4px] rounded-full bg-cyan" />
                Backend SQLite
              </span>
            </div>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <div className="relative min-w-[260px]">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-lilac/30" />
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search target, scan or ID..."
                aria-label="Search scan history"
                className="h-9 w-full rounded-[2px] border border-[#22374f] bg-[#07101d] pl-9 pr-3 text-[11px] text-paper outline-none transition placeholder:text-lilac/25 hover:border-lilac/25 focus:border-cyan/50"
              />
            </div>
            <div className="flex items-center gap-0.5 rounded-[2px] border border-lilac/12 p-0.5">
              {[
                { id: "all" as const, label: "All" },
                { id: "completed" as const, label: "Completed" },
                { id: "failed" as const, label: "Failed" },
                { id: "cancelled" as const, label: "Stopped" },
              ].map((item) => (
                <button
                  key={item.id}
                  type="button"
                  aria-pressed={filter === item.id}
                  onClick={() => setFilter(item.id)}
                  className={classNames(
                    "h-7 rounded-[3px] px-2.5 text-[9.5px] transition",
                    filter === item.id
                      ? "bg-cyan/[0.08] text-cyan"
                      : "text-lilac/35 hover:bg-white/[0.04] hover:text-lilac/65",
                  )}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {backendError ? (
          <EmptyState
            icon={ServerOff}
            title="Cannot load scan history from backend."
            description={backendError}
            action={
              <Button variant="secondary" size="sm" icon={RefreshCw} onClick={() => void refreshWorkspace()}>
                Retry connection
              </Button>
            }
          />
        ) : scans.length === 0 ? (
          <EmptyState
            icon={History}
            title="No real scan records yet. Start a new authorized investigation."
            description="Sample data is not shown in real scan history. Validate an authorized HTTP or HTTPS target and run a scan to persist a real record in SQLite."
            action={
              <ButtonLink to="/scan/new" variant="gold" size="sm" icon={Plus}>
                New investigation
              </ButtonLink>
            }
          />
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={History}
            title="No runs match this view."
            description="Clear the search or choose another status filter to see your persisted scan records."
            action={
              <button
                type="button"
                onClick={() => {
                  setFilter("all");
                  setQuery("");
                }}
                className="inline-flex h-8 items-center gap-1.5 rounded-[2px] border border-lilac/15 px-3 text-[11px] text-lilac/65 transition hover:border-lilac/30 hover:text-paper"
              >
                <RotateCcw className="size-3" /> Reset filters
              </button>
            }
          />
        ) : (
          <>
            <div className="hidden overflow-x-auto lg:block">
              <table className="w-full min-w-[1010px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-[#1a2b42] bg-[#060d18]">
                    {["Scan", "Target", "Started", "Duration", "Coverage", "Findings", "Severity mix", "Status", ""].map(
                      (heading, index) => (
                        <th
                          key={`${heading}-${index}`}
                          className={classNames(
                            "px-3 py-2.5 font-mono text-[8px] font-normal uppercase tracking-[0.12em] text-lilac/30",
                            index === 0 ? "pl-5" : "",
                            index === 8 ? "pr-5 text-right" : "",
                          )}
                        >
                          {heading}
                        </th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((scan) => {
                    const findings = getFindingsForScan(scan.id);
                    const counts = countSeverities(findings);
                    const updatedFinding = scan.verification
                      ? getFinding(scan.verification.findingId)
                      : undefined;
                    return (
                      <tr key={scan.id} className="group border-b border-[#142338] transition hover:bg-cyan/[0.018]">
                        <td className="py-4 pl-5 pr-3">
                          <button
                            type="button"
                            onClick={() => openScan(scan)}
                            className="block text-left"
                          >
                            <div className="flex items-center gap-2">
                              <span className="text-[12.5px] font-medium text-paper/85 transition group-hover:text-paper">
                                {scan.label}
                              </span>
                              {scan.rescanOfFindingId ? (
                                <span className="rounded-[3px] border border-lilac/10 px-1 py-0.5 font-mono text-[7.5px] uppercase tracking-[0.06em] text-lilac/35">
                                  rescan
                                </span>
                              ) : null}
                            </div>
                            <p className="mt-0.5 font-mono text-[8.5px] text-lilac/25">{scan.id}</p>
                          </button>
                        </td>
                        <td className="px-3 py-4">
                          <p className="max-w-[175px] truncate font-mono text-[10.5px] text-lilac/60">{hostnameOf(scan.target)}</p>
                          <p className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.06em] text-lilac/20">
                            {scan.checks.length} {pluralize(scan.checks.length, "module")}
                          </p>
                        </td>
                        <td className="px-3 py-4">
                          <p className="text-[10px] text-lilac/50">{formatDate(scan.startedAt)}</p>
                          <p className="mt-0.5 font-mono text-[8px] text-lilac/25">{formatRelative(scan.startedAt)}</p>
                        </td>
                        <td className="px-3 py-4 font-mono text-[10px] text-lilac/45">
                          {formatDuration(scan.startedAt, scan.completedAt)}
                        </td>
                        <td className="px-3 py-4">
                          <div className="flex flex-wrap gap-1">
                            {scan.checks.map((check) => (
                              <span key={check} className="rounded-[2px] border border-white/10 px-1 py-0.5 font-mono text-[7.5px] uppercase text-lilac/35">
                                {check === "headers" ? "hdr" : check === "cookies" ? "ck" : check === "paths" ? "path" : "inj"}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="px-3 py-4">
                          {scan.verification ? (
                            <div>
                              <span
                                className={classNames(
                                  "font-mono text-[8.5px] uppercase tracking-[0.06em]",
                                  scan.verification.outcome === "resolved" ? "text-good" : "text-gold",
                                )}
                              >
                                {scan.verification.outcome === "resolved" ? "resolved" : "still present"}
                              </span>
                              <p className="mt-0.5 text-[8px] text-lilac/25">{updatedFinding?.id}</p>
                            </div>
                          ) : (
                            <div>
                              <p className="font-mono text-[11px] text-paper/75">{findings.length}</p>
                              <p className="mt-0.5 text-[8px] text-lilac/25">
                                {scan.status === "completed" ? `${findings.filter((finding) => finding.status === "open").length} open` : "not produced"}
                              </p>
                            </div>
                          )}
                        </td>
                        <td className="px-3 py-4">
                          {scan.status === "completed" && !scan.verification ? (
                            <SeverityStrip counts={counts} className="w-24" showEmpty={false} />
                          ) : scan.verification ? (
                            <span className="font-mono text-[8px] uppercase tracking-[0.05em] text-lilac/25">
                              verification record
                            </span>
                          ) : (
                            <span className="font-mono text-[8px] uppercase tracking-[0.05em] text-lilac/20">n/a</span>
                          )}
                        </td>
                        <td className="px-3 py-4">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <StatusPill scan={scan} />
                            {scan.status === "completed" &&
                            scan.checkResults &&
                            Object.values(scan.checkResults).some((r) => r?.status === "scan_failed") ? (
                              <span className="rounded-[2px] border border-medium/30 bg-medium/[0.08] px-1.5 py-0.5 font-mono text-[7.5px] uppercase text-medium">
                                partial
                              </span>
                            ) : null}
                          </div>
                        </td>
                        <td className="py-4 pl-2 pr-5 text-right">
                          {scan.status === "completed" ? (
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                type="button"
                                onClick={() => navigate(`/scans/${scan.id}/progress`)}
                                className="inline-flex h-7 items-center gap-1 rounded-[2px] border border-cyan/20 px-2 font-mono text-[8.5px] uppercase tracking-[0.06em] text-cyan/80 transition hover:border-cyan/45 hover:text-cyan"
                              >
                                Results
                              </button>
                              <button
                                type="button"
                                onClick={() => void exportReport(scan, findings)}
                                disabled={Boolean(exportingId)}
                                title="Download PDF report"
                                className="inline-flex h-7 items-center gap-1 rounded-[2px] border border-lilac/12 px-2 font-mono text-[8.5px] uppercase tracking-[0.06em] text-lilac/45 transition hover:border-cyan/30 hover:text-cyan disabled:cursor-wait disabled:opacity-50"
                              >
                                {exportingId === scan.id ? (
                                  <LoaderCircle className="size-3 animate-spin" />
                                ) : (
                                  <FileDown className="size-3" />
                                )}
                                PDF
                              </button>
                              <button
                                type="button"
                                onClick={() => navigate(`/reports/${scan.id}`)}
                                className="inline-flex size-7 items-center justify-center rounded-[2px] text-lilac/30 transition hover:bg-white/[0.05] hover:text-paper"
                                aria-label={`Open report for ${scan.label}`}
                              >
                                <ChevronRight className="size-4" />
                              </button>
                            </div>
                          ) : (
                            <button
                              type="button"
                              onClick={() => openScan(scan)}
                              className="inline-flex h-7 items-center gap-1 rounded-[2px] border border-lilac/12 px-2 font-mono text-[8.5px] uppercase tracking-[0.06em] text-lilac/45 transition hover:border-lilac/30 hover:text-paper"
                            >
                              View run <ChevronRight className="size-3" />
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="divide-y divide-[#142338] lg:hidden">
              {filtered.map((scan) => {
                const findings = getFindingsForScan(scan.id);
                const counts = countSeverities(findings);
                return (
                  <div key={scan.id} className="px-4 py-4">
                    <div className="flex items-start justify-between gap-3">
                      <button type="button" onClick={() => openScan(scan)} className="min-w-0 text-left">
                        <div className="flex items-center gap-2">
                          <span className="text-[12px] font-medium text-paper/90">{scan.label}</span>
                          {scan.rescanOfFindingId ? (
                            <span className="rounded-[2px] border border-lilac/10 px-1 py-0.5 font-mono text-[7px] uppercase text-lilac/35">rescan</span>
                          ) : null}
                        </div>
                        <p className="mt-0.5 truncate font-mono text-[9px] text-lilac/35">{hostnameOf(scan.target)}</p>
                      </button>
                      <StatusPill scan={scan} />
                    </div>
                    <div className="mt-3 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2 text-[9.5px] text-lilac/30">
                        <span>{formatDateTime(scan.startedAt)}</span>
                        <span className="size-[2px] rounded-full bg-lilac/20" />
                        <span>{formatDuration(scan.startedAt, scan.completedAt)}</span>
                      </div>
                      <span className="font-mono text-[9px] text-lilac/35">
                        {scan.verification
                          ? scan.verification.outcome === "resolved"
                            ? "resolved"
                            : "still present"
                          : `${findings.length} finding${findings.length === 1 ? "" : "s"}`}
                      </span>
                    </div>
                    <div className="mt-2.5 flex items-center justify-between gap-3">
                      {scan.status === "completed" && !scan.verification ? (
                        <SeverityStrip counts={counts} className="flex-1" showEmpty={false} />
                      ) : (
                        <span className="flex-1" />
                      )}
                      {scan.status === "completed" ? (
                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => void exportReport(scan, findings)}
                            disabled={Boolean(exportingId)}
                            className="inline-flex h-7 items-center gap-1 rounded-[2px] border border-lilac/12 px-2 font-mono text-[8.5px] uppercase text-lilac/45"
                          >
                            {exportingId === scan.id ? <LoaderCircle className="size-3 animate-spin" /> : <FileDown className="size-3" />}
                            PDF
                          </button>
                          <button
                            type="button"
                            onClick={() => openScan(scan)}
                            className="inline-flex h-7 items-center gap-1 rounded-[2px] border border-lilac/12 px-2 text-[9px] text-lilac/45"
                          >
                            Report <ArrowRight className="size-3" />
                          </button>
                        </div>
                      ) : (
                        <button
                          type="button"
                          onClick={() => openScan(scan)}
                          className="inline-flex h-7 items-center gap-1 rounded-[2px] border border-lilac/12 px-2 text-[9px] text-lilac/45"
                        >
                          View run <ArrowRight className="size-3" />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-lilac/[0.08] px-5 py-3">
          <p className="flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
            <ShieldCheck className="size-3" /> PDF export runs locally from persisted records
          </p>
          <p className="flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.08em] text-lilac/25">
            Live SQLite history
          </p>
        </div>
      </Panel>
    </div>
  );
}
