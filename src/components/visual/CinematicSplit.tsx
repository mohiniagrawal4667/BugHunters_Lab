import type { ReactNode } from "react";
import { Crosshair, Radio } from "lucide-react";
import { classNames } from "../../lib/format";

export type CommandReadout = { label: string; value: string };

export function CommandVisual({
  image,
  title,
  caption,
  kicker = "Live simulation",
  readouts = [],
  imagePosition = "center",
  className,
  children,
}: {
  image: string;
  title: string;
  caption: string;
  kicker?: string;
  readouts?: CommandReadout[];
  imagePosition?: string;
  className?: string;
  children?: ReactNode;
}) {
  return (
    <div className={classNames("relative min-h-0 overflow-hidden bg-[#02050c]", className)}>
      <img
        src={image}
        alt=""
        aria-hidden="true"
        loading="eager"
        className="absolute inset-0 h-full w-full object-cover"
        style={{ objectPosition: imagePosition }}
      />
      <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(2,6,14,0.42)_0%,rgba(2,6,14,0.08)_34%,rgba(2,6,14,0.82)_78%,#02050c_100%)]" />
      <div className="absolute inset-0 bg-[linear-gradient(100deg,rgba(0,229,255,0.12),transparent_38%,rgba(255,45,141,0.14))] mix-blend-screen" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_42%,transparent_10%,rgba(2,5,12,0.38)_72%)]" />
      <div className="command-grid absolute inset-0 opacity-25" />
      <div className="rain-layer absolute inset-0 opacity-50" />
      <div className="scanline-y" />

      <div className="hud-corners absolute inset-0">
        <div className="absolute left-5 right-5 top-5 flex items-start justify-between gap-3">
          <span className="inline-flex items-center gap-2 border border-cyan/25 bg-[#02060e]/70 px-2 py-1 font-mono text-[8px] uppercase tracking-[0.18em] text-cyan/90 backdrop-blur-sm">
            <span className="signal-dot size-[4px] rounded-full bg-cyan" />
            {kicker}
          </span>
          <span className="hidden items-center gap-2 border border-magenta/20 bg-[#02060e]/55 px-2 py-1 font-mono text-[8px] uppercase tracking-[0.16em] text-magenta/80 backdrop-blur-sm sm:inline-flex">
            <Radio className="size-2.5" /> CAM 07 / Sector 04
          </span>
        </div>

        <div className="pointer-events-none absolute left-1/2 top-[43%] hidden -translate-x-1/2 -translate-y-1/2 sm:block">
          <div className="relative flex size-44 items-center justify-center rounded-full border border-cyan/15">
            <div className="absolute inset-4 rounded-full border border-dashed border-cyan/15" />
            <div className="absolute inset-10 rounded-full border border-magenta/20" />
            <span className="absolute -left-3 top-1/2 h-px w-3 bg-cyan/50" />
            <span className="absolute -right-3 top-1/2 h-px w-3 bg-cyan/50" />
            <span className="absolute -top-3 left-1/2 h-3 w-px bg-cyan/50" />
            <span className="absolute -bottom-3 left-1/2 h-3 w-px bg-cyan/50" />
            <Crosshair className="size-5 text-cyan/55" strokeWidth={1} />
            <span className="absolute right-1 top-5 font-mono text-[7px] tracking-[0.12em] text-cyan/35">TRK.0A</span>
          </div>
        </div>

        <div className="absolute bottom-0 left-0 right-0">
          <div className="px-5 pb-4">
            <p className="font-mono text-[8px] uppercase tracking-[0.22em] text-cyan/65">{caption}</p>
            <h2 className="mt-2 max-w-[420px] font-display text-[30px] font-medium uppercase leading-[0.94] tracking-[-0.035em] text-paper sm:text-[38px]">
              {title}
            </h2>
            {readouts.length > 0 ? (
              <dl className="mt-5 grid grid-cols-3 border-t border-cyan/15 bg-[#02060e]/25 backdrop-blur-[2px]">
                {readouts.map((readout) => (
                  <div key={readout.label} className="border-r border-cyan/10 px-2.5 py-2.5 last:border-r-0">
                    <dt className="truncate font-mono text-[7px] uppercase tracking-[0.14em] text-lilac/40">{readout.label}</dt>
                    <dd className="mt-1 font-mono text-[13px] uppercase text-paper/90">{readout.value}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
          </div>
        </div>
      </div>

      {children}
    </div>
  );
}
