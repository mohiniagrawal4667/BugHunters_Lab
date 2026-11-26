import type { ReactNode } from "react";
import { DemoBadge } from "./Badges";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  sample = true,
}: {
  eyebrow: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  sample?: boolean;
}) {
  return (
    <header className="relative mb-7 border-b border-[#1a2b42] pb-6">
      <span className="absolute -top-1 left-0 h-8 w-px bg-cyan shadow-[0_0_12px_rgba(0,229,255,0.6)]" aria-hidden="true" />
      <div className="flex flex-col justify-between gap-5 pl-4 sm:flex-row sm:items-end sm:pl-5">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <p className="mono-label text-cyan/65">
              <span className="mr-1.5 text-magenta/80">//</span>
              {eyebrow}
            </p>
            {sample ? <DemoBadge label="Demo data" subtle /> : null}
          </div>
          <h1 className="mt-3 max-w-3xl text-balance font-display text-[30px] font-medium leading-[1.02] tracking-[-0.045em] text-paper sm:text-[40px]">
            {title}
          </h1>
          {description ? (
            <p className="mt-3 max-w-2xl text-pretty text-[12.5px] leading-relaxed text-lilac/55 sm:text-[13px]">
              {description}
            </p>
          ) : null}
        </div>
        {actions ? (
          <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>
        ) : null}
      </div>
    </header>
  );
}
