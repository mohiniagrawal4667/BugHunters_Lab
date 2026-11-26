import { Link } from "react-router-dom";
import { ArrowLeft, Compass, FileSearch, Plus } from "lucide-react";
import { ButtonLink } from "../components/ui/Button";
import { Panel } from "../components/ui/Section";

export function NotFound() {
  return (
    <div className="mx-auto max-w-2xl py-10">
      <Panel className="animate-fade-up relative overflow-hidden px-6 py-10 text-center sm:px-10 sm:py-14">
        <div className="blueprint-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <div className="mx-auto flex size-12 items-center justify-center rounded-[9px] border border-lilac/12 bg-white/[0.025]">
            <Compass className="size-5 text-lavender/70" />
          </div>
          <p className="mt-5 font-mono text-[9px] uppercase tracking-[0.18em] text-gold/70">404 / Route not found</p>
          <h1 className="mt-2 text-[28px] font-semibold tracking-[-0.035em] text-paper">This path has no evidence.</h1>
          <p className="mx-auto mt-3 max-w-md text-[12.5px] leading-relaxed text-lilac/45">
            The page may have moved, or the link may point outside the demo workspace. Return to the
            overview or start a new scoped scan.
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-2">
            <ButtonLink to="/" variant="primary" size="md" icon={ArrowLeft}>
              Back to overview
            </ButtonLink>
            <ButtonLink to="/scan/new" variant="gold" size="md" icon={Plus}>
              New scan
            </ButtonLink>
          </div>
          <div className="mt-7 flex flex-wrap justify-center gap-3 border-t border-lilac/[0.08] pt-4 text-[10px] text-lilac/30">
            <Link to="/findings" className="inline-flex items-center gap-1 transition hover:text-paper">
              <FileSearch className="size-3" /> Findings
            </Link>
            <Link to="/reports" className="inline-flex items-center gap-1 transition hover:text-paper">
              Reports & history
            </Link>
          </div>
        </div>
      </Panel>
    </div>
  );
}
