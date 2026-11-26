import { Check, Clock3, ShieldAlert, ShieldCheck } from "lucide-react";
import type { Confidence, FindingStatus, Severity } from "../../types";
import {
  CONFIDENCE_LABEL,
  SEVERITY_LABEL,
  STATUS_LABEL,
  classNames,
} from "../../lib/format";

const severityStyles: Record<Severity, { wrap: string; dot: string }> = {
  critical: {
    wrap: "border-critical/30 bg-critical/[0.09] text-critical",
    dot: "bg-critical",
  },
  high: {
    wrap: "border-high/30 bg-high/[0.09] text-high",
    dot: "bg-high",
  },
  medium: {
    wrap: "border-medium/30 bg-medium/[0.09] text-medium",
    dot: "bg-medium",
  },
  low: {
    wrap: "border-low/30 bg-low/[0.09] text-low",
    dot: "bg-low",
  },
  informational: {
    wrap: "border-lilac/25 bg-white/[0.04] text-lilac/70",
    dot: "bg-lilac/60",
  },
};

export function SeverityBadge({
  severity,
  className,
  compact = false,
}: {
  severity: Severity;
  className?: string;
  compact?: boolean;
}) {
  const style = severityStyles[severity];
  return (
    <span
      className={classNames(
        "inline-flex items-center gap-1.5 rounded-[2px] border font-mono uppercase",
        compact ? "px-1.5 py-[3px] text-[9px] tracking-[0.12em]" : "px-2 py-1 text-[10px] tracking-[0.14em]",
        style.wrap,
        className,
      )}
    >
      <span className={classNames("size-[5px] rounded-full", style.dot)} />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function ConfidenceMeter({
  confidence,
  showLabel = true,
  className,
}: {
  confidence: Confidence;
  showLabel?: boolean;
  className?: string;
}) {
  const filled = confidence === "high" ? 3 : confidence === "medium" ? 2 : 1;
  return (
    <span className={classNames("inline-flex items-center gap-2", className)}>
      <span className="flex items-end gap-[3px]" aria-hidden="true">
        {[0, 1, 2].map((index) => (
          <span
            key={index}
            className={classNames(
              "w-[3px] rounded-full",
              index === 0 ? "h-[5px]" : index === 1 ? "h-[8px]" : "h-[11px]",
              index < filled ? "bg-lavender" : "bg-white/15",
            )}
          />
        ))}
      </span>
      {showLabel ? (
        <span className="text-[12px] text-lilac/75">{CONFIDENCE_LABEL[confidence]}</span>
      ) : null}
    </span>
  );
}

const statusStyles: Record<FindingStatus, { wrap: string; dot: string; icon: typeof Check }> = {
  open: {
    wrap: "border-critical/25 bg-critical/[0.06] text-critical",
    dot: "bg-critical",
    icon: ShieldAlert,
  },
  pending: {
    wrap: "border-gold/25 bg-gold/[0.06] text-gold",
    dot: "bg-gold",
    icon: Clock3,
  },
  resolved: {
    wrap: "border-good/25 bg-good/[0.07] text-good",
    dot: "bg-good",
    icon: ShieldCheck,
  },
};

export function StatusBadge({
  status,
  className,
}: {
  status: FindingStatus;
  className?: string;
}) {
  const style = statusStyles[status];
  return (
    <span
      className={classNames(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-[2px] border px-2 py-1 font-mono text-[9px] uppercase tracking-[0.12em]",
        style.wrap,
        className,
      )}
    >
      <span className={classNames("size-[5px] rounded-full", style.dot)} />
      {STATUS_LABEL[status]}
    </span>
  );
}

export function DemoBadge({
  label = "Sample data",
  className,
  subtle = false,
}: {
  label?: string;
  className?: string;
  subtle?: boolean;
}) {
  return (
    <span
      className={classNames(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-[2px] border font-mono uppercase tracking-[0.12em]",
        subtle
          ? "border-[#2a3a50]/80 bg-white/[0.02] px-2 py-1 text-[9px] text-lilac/55"
          : "border-magenta/30 bg-magenta/[0.06] px-2 py-1 text-[9px] text-magenta",
        className,
      )}
    >
      <span className="size-[5px] rounded-full bg-gold/80" />
      {label}
    </span>
  );
}

export function CountPill({ value, label }: { value: number; label: string }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-[2px] border border-[#2a3a50]/80 bg-white/[0.02] px-2 py-1">
      <span className="font-mono text-[11px] text-paper">{value}</span>
      <span className="text-[10px] uppercase tracking-[0.1em] text-lilac/40">{label}</span>
    </span>
  );
}
