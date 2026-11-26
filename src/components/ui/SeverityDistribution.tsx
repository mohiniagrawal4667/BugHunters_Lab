import type { Finding, Severity } from "../../types";
import { SEVERITY_LABEL, SEVERITY_ORDER, classNames, pluralize } from "../../lib/format";

export type SeverityCounts = Record<Severity, number>;

export function countSeverities(findings: Finding[]): SeverityCounts {
  return findings.reduce<SeverityCounts>(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
  );
}

const segmentStyles: Record<Severity, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  informational: "bg-lilac/50",
};

export function SeverityStrip({
  counts,
  className,
  showEmpty = true,
}: {
  counts: SeverityCounts;
  className?: string;
  showEmpty?: boolean;
}) {
  const total = SEVERITY_ORDER.reduce((sum, severity) => sum + counts[severity], 0);
  if (total === 0 && !showEmpty) return null;

  return (
    <div className={classNames("flex h-1.5 w-full gap-[2px] overflow-hidden rounded-full bg-white/[0.06]", className)}>
      {total === 0 ? (
        <span className="h-full w-full bg-white/[0.06]" />
      ) : (
        SEVERITY_ORDER.map((severity) =>
          counts[severity] > 0 ? (
            <span
              key={severity}
              className={classNames("h-full rounded-full", segmentStyles[severity])}
              style={{ width: `${(counts[severity] / total) * 100}%` }}
              title={`${counts[severity]} ${SEVERITY_LABEL[severity]}`}
            />
          ) : null,
        )
      )}
    </div>
  );
}

export function SeverityLegend({
  counts,
  className,
  compact = false,
}: {
  counts: SeverityCounts;
  className?: string;
  compact?: boolean;
}) {
  return (
    <div className={classNames("flex flex-wrap items-center gap-x-4 gap-y-2", className)}>
      {SEVERITY_ORDER.map((severity) => (
        <span key={severity} className="inline-flex items-center gap-1.5">
          <span className={classNames("size-[5px] rounded-full", segmentStyles[severity])} />
          <span className={compact ? "text-[10px] text-lilac/45" : "text-[11px] text-lilac/55"}>
            {SEVERITY_LABEL[severity]}
          </span>
          <span className="font-mono text-[10.5px] text-paper/80">{counts[severity]}</span>
        </span>
      ))}
    </div>
  );
}

export function severitySummaryText(counts: SeverityCounts): string {
  const total = SEVERITY_ORDER.reduce((sum, severity) => sum + counts[severity], 0);
  return `${total} ${pluralize(total, "finding")}`;
}
