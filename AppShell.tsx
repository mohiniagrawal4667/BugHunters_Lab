import { useEffect, useState } from "react";
import { NavLink, Outlet, Link, useLocation } from "react-router-dom";
import { ArrowUpRight, Menu, Plus, ShieldCheck, X } from "lucide-react";
import { LogoLockup, LogoMark } from "./brand/Logo";
import { ConnectionModal } from "./ConnectionModal";
import { classNames } from "../lib/format";

const primaryNav = [
  { to: "/", label: "Overview", code: "01", end: true },
  { to: "/scan/new", label: "Investigate", code: "02", end: true },
  { to: "/findings", label: "Evidence", code: "03", end: false },
  { to: "/reports", label: "Case records", code: "04", end: false },
];

const moduleNav = [
  { to: "/scan/new?checks=headers", label: "Header inspector", code: "M.01" },
  { to: "/scan/new?checks=cookies", label: "Cookie analyzer", code: "M.02" },
  { to: "/scan/new?checks=paths", label: "Exposed paths", code: "M.03" },
  { to: "/scan/new?checks=injection", label: "Injection tester", code: "M.04" },
];

function useBreadcrumb() {
  const { pathname } = useLocation();
  if (pathname === "/") return "Investigation HQ";
  if (pathname === "/scan/new") return "New investigation";
  if (pathname.endsWith("/progress")) return "Live operation";
  if (pathname === "/findings") return "Evidence log";
  if (pathname.startsWith("/findings/")) return "Evidence file";
  if (pathname === "/reports") return "Case records";
  if (pathname.startsWith("/reports/")) return "Scan report";
  return "Workspace";
}

function useUtcClock() {
  const [time, setTime] = useState("--:--:--");
  useEffect(() => {
    const tick = () => {
      setTime(
        new Date().toLocaleTimeString("en-GB", {
          hour12: false,
          timeZone: "UTC",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
      );
    };
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, []);
  return time;
}

function MobileNav({
  open,
  onClose,
  onDemo,
}: {
  open: boolean;
  onClose: () => void;
  onDemo: () => void;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[60] lg:hidden">
      <button
        type="button"
        aria-label="Close navigation"
        className="absolute inset-0 bg-[#101a2c]/40 backdrop-blur-[2px]"
        onClick={onClose}
      />
      <div className="animate-fade-in absolute inset-y-0 right-0 flex w-[88%] max-w-[420px] flex-col border-l border-[#101a2c] bg-[#f4f1e9]">
        <div className="flex h-[72px] items-center justify-between border-b border-[#c9c3b5] px-5">
          <LogoLockup compact />
          <button
            type="button"
            onClick={onClose}
            aria-label="Close menu"
            className="border border-[#bdb7a8] p-2 text-[#151923] transition hover:border-[#151923]"
          >
            <X className="size-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-7">
          <p className="mono-label text-[#8a8578]">Navigate / index</p>
          <nav className="mt-4" aria-label="Primary mobile">
            {primaryNav.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={onClose}
                className={({ isActive }) =>
                  classNames(
                    "flex items-baseline gap-4 border-b border-[#d4cec0] py-3.5",
                    isActive ? "text-[#101a2c]" : "text-[#5d6978]",
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <span className={classNames("font-mono text-[9px]", isActive ? "text-[#007e90]" : "text-[#a39c8d]")}>
                      {item.code}
                    </span>
                    <span className="font-display text-[30px] font-medium leading-none tracking-[-0.04em]">
                      {item.label}
                    </span>
                    {isActive ? <span className="ml-auto size-1.5 bg-[#f52d8a]" /> : null}
                  </>
                )}
              </NavLink>
            ))}
          </nav>

          <div className="mt-8 flex items-center justify-between">
            <p className="mono-label text-[#8a8578]">Scanner modules</p>
            <span className="font-mono text-[9px] text-[#007e90]">04 armed</span>
          </div>
          <div className="mt-3 grid grid-cols-2 gap-px border border-[#d4cec0] bg-[#d4cec0]">
            {moduleNav.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                onClick={onClose}
                className="bg-[#fafaf7] p-3 transition hover:bg-white"
              >
                <span className="font-mono text-[8px] text-[#f52d8a]">{item.code}</span>
                <span className="mt-1.5 block font-display text-[13px] leading-tight tracking-[-0.01em] text-[#151923]">
                  {item.label}
                </span>
              </Link>
            ))}
          </div>

          <button
            type="button"
            onClick={() => {
              onClose();
              onDemo();
            }}
            className="mt-6 w-full border border-[#f52d8a]/40 bg-[#f52d8a]/[0.04] p-4 text-left"
          >
            <span className="flex items-center justify-between">
              <span className="mono-label text-[#b41860]">Demo workspace</span>
              <ArrowUpRight className="size-3.5 text-[#b41860]" />
            </span>
            <span className="mt-2 block text-[11px] leading-relaxed text-[#5d6978]">
              No backend connected. Scans run locally and every finding is sample evidence.
            </span>
          </button>
        </div>

        <div className="border-t border-[#c9c3b5] px-5 py-4">
          <p className="font-mono text-[8px] uppercase tracking-[0.14em] text-[#8a8578]">
            RAVENX 2026 / Team Masala Dosa
          </p>
        </div>
      </div>
    </div>
  );
}

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [connectionOpen, setConnectionOpen] = useState(false);
  const location = useLocation();
  const breadcrumb = useBreadcrumb();
  const utc = useUtcClock();

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname, location.search]);

  useEffect(() => {
    const openConnection = () => setConnectionOpen(true);
    window.addEventListener("bhl:open-connection", openConnection);
    return () => window.removeEventListener("bhl:open-connection", openConnection);
  }, []);

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-50 border-b border-[#c9c3b5] bg-[#f4f1e9]/95 backdrop-blur-xl">
        <div className="mx-auto flex h-[68px] w-full max-w-[1600px] items-center justify-between gap-6 px-5 sm:px-7 lg:h-[78px] lg:px-10">
          <LogoLockup />

          <nav className="hidden h-full items-stretch lg:flex" aria-label="Primary">
            {primaryNav.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  classNames(
                    "group relative flex items-center gap-2 px-5 text-[11px] font-medium uppercase tracking-[0.09em] transition-colors",
                    isActive ? "text-[#101a2c]" : "text-[#6c756f] hover:text-[#101a2c]",
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <span className={classNames("font-mono text-[8px]", isActive ? "text-[#007e90]" : "text-[#aaa394]")}>
                      {item.code}
                    </span>
                    <span>{item.label}</span>
                    <span
                      className={classNames(
                        "absolute inset-x-5 bottom-0 h-[2px] transition-transform",
                        isActive ? "scale-x-100 bg-[#101a2c]" : "scale-x-0 bg-[#101a2c] group-hover:scale-x-100",
                      )}
                    />
                  </>
                )}
              </NavLink>
            ))}
          </nav>

          <div className="flex items-center gap-2.5 sm:gap-4">
            <div className="hidden items-center gap-2 border-r border-[#d8d3c6] pr-4 xl:flex">
              <span className="soft-pulse size-[5px] rounded-full bg-[#0b7456]" />
              <span className="font-mono text-[8.5px] uppercase tracking-[0.14em] text-[#6c756f]">
                {utc} UTC
              </span>
            </div>
            <button
              type="button"
              onClick={() => setConnectionOpen(true)}
              className="hidden h-8 items-center gap-2 border border-[#f52d8a]/35 px-2.5 transition hover:border-[#f52d8a] hover:bg-[#f52d8a]/[0.04] sm:inline-flex"
              title="Demo mode - no backend connected"
            >
              <span className="size-[5px] rounded-full bg-[#f52d8a]" />
              <span className="font-mono text-[8.5px] uppercase tracking-[0.13em] text-[#b41860]">
                Demo
              </span>
            </button>
            <Link
              to="/scan/new"
              className="group hidden h-9 items-center gap-3 bg-[#101a2c] px-4 text-[10.5px] font-semibold uppercase tracking-[0.1em] text-[#f4f1e9] transition hover:bg-[#172c45] sm:inline-flex"
            >
              New scan
              <ArrowUpRight className="size-3.5 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
            </Link>
            <Link
              to="/scan/new"
              aria-label="New investigation"
              className="inline-flex size-9 items-center justify-center bg-[#101a2c] text-[#f4f1e9] sm:hidden"
            >
              <Plus className="size-4" />
            </Link>
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation"
              className="inline-flex size-9 items-center justify-center border border-[#bdb7a8] text-[#151923] lg:hidden"
            >
              <Menu className="size-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="border-b border-[#d8d3c6] bg-[#fafaf7]">
        <div className="mx-auto flex h-8 w-full max-w-[1600px] items-center justify-between gap-4 px-5 sm:px-7 lg:px-10">
          <p className="truncate font-mono text-[8.5px] uppercase tracking-[0.14em] text-[#8a8578]">
            HQ / NODE 07 <span className="mx-2 text-[#c9c3b5]">/</span>{" "}
            <span className="text-[#007e90]">{breadcrumb}</span>
          </p>
          <p className="hidden font-mono text-[8.5px] uppercase tracking-[0.14em] text-[#8a8578] sm:block">
            Local engine / non-destructive / authorized targets only
          </p>
        </div>
      </div>

      <main className="mx-auto w-full max-w-[1600px] flex-1 px-5 py-8 sm:px-7 lg:px-10 lg:py-12">
        <Outlet />
      </main>

      <footer className="bg-[#101a2c] text-[#f4f1e9]">
        <div className="mx-auto grid w-full max-w-[1600px] gap-8 px-5 py-10 sm:px-7 md:grid-cols-[1.4fr_1fr_1fr] lg:px-10 lg:py-12">
          <div>
            <div className="flex items-center gap-3">
              <LogoMark size={28} />
              <span className="font-display text-[15px] font-semibold uppercase tracking-[0.12em]">
                Bug Hunter Lab
              </span>
            </div>
            <p className="mt-4 max-w-[340px] text-[13px] leading-relaxed text-[#b8c0ca]">
              An evidence-first web vulnerability scanner. Built for authorized investigation,
              not blind automation.
            </p>
          </div>
          <div>
            <p className="font-mono text-[8.5px] uppercase tracking-[0.16em] text-[#7f8b99]">Protocol</p>
            <p className="mt-3 font-display text-[20px] leading-tight tracking-[-0.02em]">
              Don't just detect.
              <br />
              Prove. Fix. Verify.
            </p>
          </div>
          <div className="flex flex-col justify-between gap-5">
            <div className="flex items-start gap-2.5 text-[#b8c0ca]">
              <ShieldCheck className="mt-0.5 size-4 shrink-0 text-[#00cfe8]" />
              <p className="text-[11px] leading-relaxed">
                Authorized targets only. Non-destructive checks. Demo data is always labelled.
              </p>
            </div>
            <p className="font-mono text-[8.5px] uppercase tracking-[0.14em] text-[#7f8b99]">
              RAVENX 2026 / PS-4 / GLA University
            </p>
          </div>
        </div>
      </footer>

      <MobileNav
        open={mobileOpen}
        onClose={() => setMobileOpen(false)}
        onDemo={() => setConnectionOpen(true)}
      />
      <ConnectionModal open={connectionOpen} onClose={() => setConnectionOpen(false)} />
    </div>
  );
}
