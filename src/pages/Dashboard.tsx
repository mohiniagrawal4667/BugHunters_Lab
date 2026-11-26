import { Link } from "react-router-dom";
import {
  ArrowRight,
  ArrowUpRight,
  BadgeCheck,
  ChevronRight,
  CircleDot,
  Clock3,
  Eye,
  FileSearch,
  Plus,
  ShieldCheck,
  Terminal,
  Wrench,
} from "lucide-react";
import { useWorkspace } from "../store/WorkspaceStore";
import { ButtonLink } from "../components/ui/Button";
import { ConfidenceMeter, SeverityBadge } from "../components/ui/Badges";
import { SeverityStrip, countSeverities } from "../components/ui/SeverityDistribution";
import { Panel, PanelHeader, SectionLabel } from "../components/ui/Section";
import { CommandVisual } from "../components/visual/CinematicSplit";
import {
  CATEGORY_LABEL,
  classNames,
  confidenceRank,
  formatRelative,
  hostnameOf,
  severityRank,
} from "../lib/format";
import type { Scan } from "../types";

const scanStatusStyle: Record<Scan["status"], string> = {
  completed: "text-good",
  running: "text-cyan",
  failed: "text-critical",
  cancelled: "text-lilac/45",
};

const scanStatusLabel: Record<Scan["status"], string> = {
  completed: "Complete",
  running: "Running",
  failed: "Failed",
  cancelled: "Stopped",
};

function StatCell({
  code,
  label,
  value,
  detail,
  accent,
}: {
  code: string;
  label: string;
  value: string | number;
  detail?: string;
  accent?: string;
}) {
  return (
    <div className="relative min-h-[104px] overflow-hidden border-b border-r border-[#172840] px-4 py-3.5 last:border-r-0">
      <span className="pointer-events-none absolute -right-1 -top-2 font-display text-[44px] font-medium leading-none text-white/[0.025]">
        {code}
      </span>
      <div className="flex items-center gap-2">
        {accent ? <span className={classNames("size-[5px] rounded-full", accent)} /> : <span className="size-[5px] rounded-full bg-cyan/60" />}
        <p className="mono-label text-lilac/40">{label}</p>
      </div>
      <p className="mt-5 font-display text-[30px] font-medium leading-none tracking-[-0.05em] text-paper">
        {value}
      </p>
      {detail ? <p className="mt-2 text-[9.5px] text-lilac/35">{detail}</p> : null}
    </div>
  );
}

export function Dashboard() {
  const { scans, findings, latestPrimaryScan, getFindingsForScan, backendError } = useWorkspace();
  const latest = latestPrimaryScan;
  const latestFindings = latest ? getFindingsForScan(latest.id) : [];
  const counts = countSeverities(latestFindings);
  const allCounts = countSeverities(findings);
  const completedScans = scans.filter((scan) => scan.status === "completed").length;
  const failedScans = scans.filter((scan) => scan.status === "failed").length;
  const resolved = latestFindings.filter((finding) => finding.status === "resolved").length;
  const sortedFindings = [...latestFindings]
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        confidenceRank(a.confidence) - confidenceRank(b.confidence),
    )
    .slice(0, 5);
  const recentScans = [...scans]
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())
    .slice(0, 4);
  const openCount = latestFindings.filter((finding) => finding.status !== "resolved").length;
  const totalScans = scans.length;
  const totalRequests = scans.reduce((sum, scan) => sum + (scan.requestCount ?? 0), 0);
  const primaryTarget = latest ? hostnameOf(latest.target) : "no target";
  const resumedCount = scans.filter((scan) => scan.verification).length;

  return (
    <div className="space-y-6">
      <section className="tactical-panel animate-fade-up overflow-hidden">
        <div className="grid lg:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)]">
          <CommandVisual
            image="/brand/city-night.jpg"
            title="Night watch"
            caption="Digital city / live investigation"
            kicker={backendError ? "Backend offline" : "SQLite backed"}
            imagePosition="50% 46%"
            className="h-[330px] border-b border-cyan/15 sm:h-[390px] lg:h-auto lg:min-h-[600px] lg:border-b-0 lg:border-r"
            readouts={[
              { label: "Persisted scans", value: String(totalScans).padStart(2, "0") },
              { label: "Checks armed", value: "04" },
              { label: "HTTP requests", value: String(totalRequests).padStart(2, "0") },
            ]}
          />

          <div className="relative flex flex-col justify-between overflow-hidden bg-[#060c17] p-6 sm:p-8 lg:p-10">
            <div className="command-grid absolute inset-0 opacity-[0.18]" aria-hidden="true" />
            <div className="absolute -right-24 -top-24 size-72 rounded-full bg-cyan/[0.045] blur-3xl" aria-hidden="true" />
            <div className="absolute -bottom-28 left-1/4 size-72 rounded-full bg-magenta/[0.04] blur-3xl" aria-hidden="true" />

            <div className="relative">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <span className="font-mono text-[8.5px] uppercase tracking-[0.2em] text-lilac/40">
                  Investigation headquarters / RAVENX 2026
                </span>
                <span
                  className={classNames(
                    "inline-flex items-center gap-1.5 rounded-[2px] border px-2 py-1 font-mono text-[8.5px] uppercase tracking-[0.12em]",
                    backendError
                      ? "border-critical/30 bg-critical/[0.06] text-critical"
                      : "border-cyan/25 bg-cyan/[0.05] text-cyan",
                  )}
                >
                  <span className="size-[5px] rounded-full bg-current" />
                  {backendError ? "Backend offline" : "Live SQLite workspace"}
                </span>
              </div>

              <div className="mt-8 flex items-center gap-3">
                <span className="h-px w-8 bg-magenta/80" />
                <span className="mono-label text-magenta/85">Case intake / active</span>
              </div>

              <h1 className="mt-4 max-w-[620px] text-balance font-display text-[40px] font-medium leading-[0.94] tracking-[-0.055em] text-paper sm:text-[52px] lg:text-[58px]">
                Every system
                <br />
                leaves{" "}
                <span className="relative inline-block text-cyan text-glow-cyan">
                  evidence.
                  <span className="absolute -bottom-1 left-0 h-px w-full bg-[linear-gradient(90deg,#00e5ff,transparent)]" />
                </span>
              </h1>

              <p className="mt-5 max-w-[510px] text-pretty text-[13px] leading-relaxed text-lilac/55">
                A page can load perfectly and still leak a session, expose a backup or hide a weak
                header. Enter the investigation environment, run four scoped checks and follow the
                raw observation behind every signal.
              </p>
              <p className="mt-3 font-mono text-[9px] uppercase tracking-[0.2em] text-cyan/45">
                Don't just detect. Prove. Fix. Verify.
              </p>

              <div className="mt-7 flex flex-wrap items-center gap-2.5">
                <ButtonLink to="/scan/new" variant="gold" size="md" icon={Plus}>
                  New investigation
                </ButtonLink>
                <ButtonLink to="/findings" variant="secondary" size="md" iconRight={ArrowRight}>
                  Open evidence log
                </ButtonLink>
                <span className="ml-1 hidden items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.1em] text-lilac/30 xl:flex">
                  <ShieldCheck className="size-3.5 text-good/60" />
                  Authorized targets / SSRF protected
                </span>
              </div>
            </div>

            <div className="relative mt-8 border border-cyan/15 bg-[#030810]/75">
              <div className="flex items-center justify-between gap-3 border-b border-[#172840] px-3.5 py-2.5">
                <span className="flex items-center gap-2 font-mono text-[8px] uppercase tracking-[0.16em] text-cyan/70">
                  <CircleDot className="size-3" /> Current case
                </span>
                <span className="font-mono text-[8px] uppercase tracking-[0.14em] text-lilac/30">
                  {latest ? `${latest.label} / ${formatRelative(latest.completedAt ?? latest.startedAt)}` : "No active case"}
                </span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4">
                <div className="border-b border-r border-[#142338] px-3.5 py-3 sm:border-b-0">
                  <p className="font-mono text-[7.5px] uppercase tracking-[0.14em] text-lilac/35">Target</p>
                  <p className="mt-1.5 truncate font-mono text-[10px] text-paper/85">{primaryTarget}</p>
                </div>
                <div className="border-b border-r border-[#142338] px-3.5 py-3 sm:border-b-0">
                  <p className="font-mono text-[7.5px] uppercase tracking-[0.14em] text-lilac/35">Signals</p>
                  <p className="mt-1.5 font-mono text-[13px] text-paper">{latestFindings.length}</p>
                </div>
                <div className="border-r border-[#142338] px-3.5 py-3">
                  <p className="font-mono text-[7.5px] uppercase tracking-[0.14em] text-lilac/35">Open</p>
                  <p className="mt-1.5 font-mono text-[13px] text-critical">{openCount}</p>
                </div>
                <div className="px-3.5 py-3">
                  <p className="font-mono text-[7.5px] uppercase tracking-[0.14em] text-lilac/35">Resolved</p>
                  <p className="mt-1.5 font-mono text-[13px] text-good">{resolved}</p>
                </div>
              </div>
              <SeverityStrip counts={counts} className="h-[3px]" showEmpty={false} />
            </div>
          </div>
        </div>
      </section>

      <section className="animate-fade-up delay-1">
        <div className="mb-2.5 flex flex-wrap items-end justify-between gap-2">
          <div className="flex items-center gap-2">
            <SectionLabel>System readout</SectionLabel>
            <span className="hidden h-px w-8 bg-[#24374f] sm:block" />
            <span className="hidden font-mono text-[8.5px] uppercase tracking-[0.12em] text-lilac/30 sm:inline">
              {totalScans > 0 ? `${completedScans} completed · ${failedScans} failed` : "No scans persisted"}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-cyan/60">
              Backend SQLite
            </span>
            <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-lilac/25">
              {resumedCount} verification runs
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 overflow-hidden border border-[#1b2c44] bg-[#060d18] sm:grid-cols-3 xl:grid-cols-6">
          <StatCell
            code="01"
            label="Total scans"
            value={totalScans}
            detail={`${completedScans} completed · ${failedScans} failed`}
          />
          <StatCell
            code="02"
            label="Evidence records"
            value={findings.length}
            detail={`Across ${totalScans} persisted scan${totalScans === 1 ? "" : "s"}`}
          />
          <StatCell code="03" label="Critical" value={allCounts.critical} accent="bg-critical" detail="Immediate review" />
          <StatCell code="04" label="High" value={allCounts.high} accent="bg-high" detail="Fix before release" />
          <StatCell code="05" label="Medium" value={allCounts.medium} accent="bg-medium" detail="Context-dependent" />
          <StatCell
            code="06"
            label="Low / Info"
            value={allCounts.low + allCounts.informational}
            accent="bg-low"
            detail="Hardening & info"
          />
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,0.7fr)]">
        <Panel className="animate-fade-up delay-2">
          <PanelHeader
            eyebrow="Case activity / last 04"
            title="Recent investigations"
            description={
              latest
                ? `Latest completed case: ${latest.label}. Open a case file, inspect evidence or export the record.`
                : "No completed scan yet."
            }
            action={
              <Link
                to="/reports"
                className="inline-flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-cyan/65 transition hover:text-cyan"
              >
                All records <ArrowUpRight className="size-3" />
              </Link>
            }
          />
          <div className="divide-y divide-[#142338]">
            {recentScans.length === 0 ? (
              <div className="px-5 py-10">
                <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-lilac/40">
                  {backendError ? "Backend unavailable" : "No real scan records yet"}
                </p>
                <p className="mt-2 text-[11px] leading-relaxed text-lilac/30">
                  {backendError
                    ? backendError
                    : "Start a new authorized investigation to persist real scan records in SQLite."}
                </p>
              </div>
            ) : (
              recentScans.map((scan) => {
                const scanFindings = getFindingsForScan(scan.id);
                const scanCounts = countSeverities(scanFindings);
                const target = `/scans/${scan.id}/progress`;
                return (
                  <Link
                    key={scan.id}
                    to={target}
                    className="group relative block px-5 py-4 transition hover:bg-cyan/[0.025]"
                  >
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                      <span className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-cyan/55">
                        {scan.label}
                      </span>
                      <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-lilac/25">
                        {formatRelative(scan.startedAt)}
                      </span>
                      <span className={classNames("ml-auto font-mono text-[8px] uppercase tracking-[0.12em]", scanStatusStyle[scan.status])}>
                        {scanStatusLabel[scan.status]}
                      </span>
                      <ChevronRight className="size-3.5 text-lilac/20 transition group-hover:translate-x-0.5 group-hover:text-cyan" />
                    </div>
                    <div className="mt-2.5 flex flex-wrap items-end justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate font-mono text-[12px] text-paper/90">{hostnameOf(scan.target)}</p>
                        <p className="mt-1 truncate font-mono text-[8.5px] text-lilac/30">{scan.target}</p>
                      </div>
                      <span className="font-mono text-[9px] uppercase tracking-[0.1em] text-lilac/40">
                        {scan.verification
                          ? scan.verification.outcome === "resolved"
                            ? "resolved"
                            : "still present"
                          : `${scanFindings.length} finding${scanFindings.length === 1 ? "" : "s"}`}
                      </span>
                    </div>
                    <div className="mt-3 flex items-center gap-3">
                      <SeverityStrip counts={scanCounts} className="flex-1" showEmpty={false} />
                      <span className="font-mono text-[8px] text-lilac/25">
                        {scan.checks.length} modules / {formatRelative(scan.completedAt ?? scan.startedAt)}
                      </span>
                    </div>
                  </Link>
                );
              })
            )}
          </div>
        </Panel>

        <Panel className="animate-fade-up delay-3">
          <PanelHeader
            eyebrow="Evidence queue / prioritised"
            title="Latest detected signals"
            action={
              <Link
                to="/findings"
                className="inline-flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-cyan/65 transition hover:text-cyan"
              >
                Inspect <ArrowRight className="size-3" />
              </Link>
            }
          />
          {sortedFindings.length === 0 ? (
            <div className="px-5 py-10">
              <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-lilac/40">No evidence acquired</p>
              <p className="mt-2 text-[11px] leading-relaxed text-lilac/30">
                Complete an investigation to populate the evidence queue.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[#142338]">
              {sortedFindings.map((finding) => {
                const category = CATEGORY_LABEL[finding.category];
                return (
                  <Link
                    key={finding.id}
                    to={`/findings/${finding.id}`}
                    className="group flex gap-3 border-l-2 border-transparent px-4 py-3.5 transition hover:border-cyan/50 hover:bg-cyan/[0.025]"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={finding.severity} compact />
                        <span className="font-mono text-[7.5px] uppercase tracking-[0.1em] text-lilac/30">{category}</span>
                      </div>
                      <p className="mt-2 line-clamp-2 text-[11.5px] font-medium leading-snug text-paper/85 group-hover:text-paper">
                        {finding.title}
                      </p>
                      <div className="mt-2 flex items-center gap-2">
                        <span className="truncate font-mono text-[8px] text-lilac/30">{finding.targetPath}</span>
                        <span className="ml-auto shrink-0 font-mono text-[7.5px] text-lilac/25">{finding.id}</span>
                      </div>
                    </div>
                    <ConfidenceMeter confidence={finding.confidence} showLabel={false} className="mt-0.5 self-start" />
                  </Link>
                );
              })}
            </div>
          )}
          <div className="flex items-center justify-between border-t border-[#142338] px-4 py-2.5">
            <span className="font-mono text-[7.5px] uppercase tracking-[0.12em] text-lilac/25">Live evidence / SQLite</span>
            <span className="font-mono text-[7.5px] text-cyan/35">{latest?.label ?? "no case"}</span>
          </div>
        </Panel>
      </div>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_310px]">
        <Panel className="animate-fade-up delay-3">
          <PanelHeader
            eyebrow="Investigation method / 05 stages"
            title="From signal to verified fix"
            description="The same chain of custody behind every finding: observe, compare, explain, remediate, verify."
          />
          <div className="grid sm:grid-cols-2 xl:grid-cols-5">
            {[
              { number: "01", title: "Observe", body: "Capture the exact response, header or cookie attribute.", icon: Eye },
              { number: "02", title: "Compare", body: "Use baselines so status codes and reflections are not proof.", icon: FileSearch },
              { number: "03", title: "Explain", body: "Attach impact, severity and confidence rationale.", icon: Terminal },
              { number: "04", title: "Remediate", body: "Give a concrete, framework-aware fix.", icon: Wrench },
              { number: "05", title: "Verify", body: "Rescan and record whether the signal is still present.", icon: BadgeCheck },
            ].map((step, index) => (
              <div
                key={step.number}
                className={classNames(
                  "relative border-b border-[#142338] px-5 py-4 last:border-b-0 sm:border-r sm:last:border-r-0 xl:border-b-0",
                  index >= 3 ? "sm:border-b-0" : "",
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[8px] text-magenta/65">{step.number}</span>
                  <step.icon className="size-3.5 text-cyan/35" strokeWidth={1.6} />
                </div>
                <p className="mt-3 font-display text-[12.5px] font-medium text-paper/90">{step.title}</p>
                <p className="mt-1 text-[10px] leading-relaxed text-lilac/35">{step.body}</p>
              </div>
            ))}
          </div>
        </Panel>

        <Panel className="animate-fade-up delay-4">
          <div className="flex items-center justify-between border-b border-[#1a2b42] px-4 py-3">
            <SectionLabel>Perimeter</SectionLabel>
            <span className="font-mono text-[8px] uppercase tracking-[0.12em] text-good/65">Enforced</span>
          </div>
          <div className="p-4">
            <p className="font-display text-[15px] font-medium text-paper">Authorized scope</p>
            <p className="mt-1 text-[10.5px] leading-relaxed text-lilac/40">
              Dynamic HTTP/HTTPS targets validated by the FastAPI SSRF & DNS gate before any request is sent.
            </p>
            <div className="mt-4 space-y-2">
              {[
                "Public HTTP/HTTPS targets (ports 80/443)",
                "Private, loopback & link-local IPs blocked",
                "IP-pinned requests & validated redirects",
              ].map((rule) => (
                <div key={rule} className="flex items-center gap-2 border border-[#1a2b42] bg-[#030810] px-2.5 py-2">
                  <span className="size-[4px] rounded-full bg-good/80" />
                  <span className="truncate font-mono text-[9px] text-lilac/65">{rule}</span>
                  <ShieldCheck className="ml-auto size-3 shrink-0 text-good/55" />
                </div>
              ))}
            </div>
            <div className="mt-4 flex items-center gap-2 border-t border-[#142338] pt-3">
              <Clock3 className="size-3 text-lilac/30" />
              <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-lilac/30">
                {backendError ? "Backend offline" : `${totalScans} persisted scan${totalScans === 1 ? "" : "s"}`}
              </span>
            </div>
          </div>
        </Panel>
      </section>
    </div>
  );
}
