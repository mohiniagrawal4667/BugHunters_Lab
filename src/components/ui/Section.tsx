import type { ReactNode } from "react";
import { classNames } from "../../lib/format";

export function Panel({
  children,
  className,
  raised = false,
}: {
  children: ReactNode;
  className?: string;
  raised?: boolean;
}) {
  return (
    <div
      className={classNames("overflow-hidden", raised ? "panel-raised" : "panel", className)}
    >
      {children}
    </div>
  );
}

export function PanelHeader({
  eyebrow,
  title,
  description,
  action,
  className,
}: {
  eyebrow?: string;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={classNames(
        "flex flex-wrap items-start justify-between gap-4 border-b border-[#1a2b42] bg-[#08111e]/60 px-5 py-4",
        className,
      )}
    >
      <div className="min-w-0">
        {eyebrow ? <p className="mono-label text-cyan/55">{eyebrow}</p> : null}
        <h2 className="mt-1 font-display text-[15px] font-medium tracking-[-0.01em] text-paper">{title}</h2>
        {description ? (
          <p className="mt-1 max-w-xl text-[12px] leading-relaxed text-lilac/50">{description}</p>
        ) : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function SectionLabel({
  children,
  index,
  className,
}: {
  children: ReactNode;
  index?: string;
  className?: string;
}) {
  return (
    <div className={classNames("flex items-center gap-2", className)}>
      <span className="h-px w-4 bg-cyan/40" aria-hidden="true" />
      {index ? (
        <span className="font-mono text-[9px] text-magenta/90">{index}</span>
      ) : null}
      <span className="font-mono text-[9.5px] uppercase tracking-[0.2em] text-lilac/60">
        {children}
      </span>
    </div>
  );
}

export function Divider({ className }: { className?: string }) {
  return <div className={classNames("h-px w-full bg-lilac/[0.08]", className)} />;
}
