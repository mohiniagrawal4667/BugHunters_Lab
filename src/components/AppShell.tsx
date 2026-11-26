import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  ChevronRight,
  CircleDot,
  Cookie,
  FileSearch,
  FileText,
  FlaskConical,
  LayoutDashboard,
  Menu,
  Plus,
  ScanLine,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import { LogoLockup, LogoMark } from "./brand/Logo";
import { ButtonLink } from "./ui/Button";
import { ConnectionModal } from "./ConnectionModal";
import { classNames } from "../lib/format";
import { checkBackendHealth } from "../services/api";

const primaryNav = [
  { to: "/", label: "Investigation HQ", icon: LayoutDashboard, end: true, code: "00" },
  { to: "/scan/new", label: "New investigation", icon: Plus, end: true, code: "01" },
  { to: "/findings", label: "Evidence log", icon: FileSearch, end: true, code: "02" },
  { to: "/reports", label: "Case records", icon: FileText, end: true, code: "03" },
];

const moduleNav = [
  { id: "headers", to: "/scan/new?checks=headers", label: "Header inspector", icon: ScanLine, code: "01" },
  { id: "cookies", to: "/scan/new?checks=cookies", label: "Cookie analyzer", icon: Cookie, code: "02" },
  { id: "paths", to: "/scan/new?checks=paths", label: "Exposed paths", icon: FileSearch, code: "03" },
  { id: "injection", to: "/scan/new?checks=injection", label: "Injection tester", icon: Terminal, code: "04" },
];

function useBreadcrumb() {
  const { pathname } = useLocation();
  if (pathname === "/") return "Investigation HQ";
  if (pathname === "/scan/new") return "Target acquisition";
  if (pathname.endsWith("/progress")) return "Live operation";
  if (pathname === "/findings") return "Evidence log";
  if (pathname.startsWith("/findings/")) return "Case file";
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

function SidebarContent({ onNavigate, backendOnline }: { onNavigate?: () => void; backendOnline: boolean | null }) {
  const { pathname, search } = useLocation();
  const activeModule = new URLSearchParams(search).get("checks");

  return (
    <div className="flex h-full min-h-0 flex-col bg-[#040912]">
      <div className="relative border-b border-[#16263c] px-5 py-5">
        <LogoLockup />
        <div className="mt-4 flex items-center justify-between font-mono text-[8px] uppercase tracking-[0.18em]">
          <span className={classNames("flex items-center gap-1.5", backendOnline ? "text-good/75" : "text-magenta/75")}>
            <span className={classNames("signal-dot size-[4px] rounded-full", backendOnline ? "bg-good" : "bg-magenta")} />
            {backendOnline ? "API + SQLite" : "API offline"}
          </span>
          <span className="text-lilac/25">v1.0 / live</span>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-3 py-5">
        <div className="flex items-center justify-between px-2.5">
          <p className="mono-label text-lilac/35">Command</p>
          <span className="font-mono text-[8px] text-cyan/30">NAV.00</span>
        </div>
        <nav className="mt-2.5 space-y-1" aria-label="Primary">
          {primaryNav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={onNavigate}
              className={({ isActive }) =>
                classNames(
                  "group relative flex h-10 items-center gap-3 border border-transparent px-2.5 text-[12px] transition-all",
                  isActive
                    ? "border-cyan/15 bg-cyan/[0.055] text-paper"
                    : "text-lilac/55 hover:border-[#1b2c44] hover:bg-white/[0.02] hover:text-paper",
                )
              }
            >
              {({ isActive }) => (
                <>
                  <span
                    className={classNames(
                      "absolute inset-y-1.5 left-0 w-px transition",
                      isActive ? "bg-cyan shadow-[0_0_10px_rgba(0,229,255,0.8)]" : "bg-transparent",
                    )}
                  />
                  <item.icon
                    className={classNames("size-[15px]", isActive ? "text-cyan" : "text-lilac/35")}
                    strokeWidth={1.7}
                  />
                  <span className="flex-1">{item.label}</span>
                  <span className={classNames("font-mono text-[8px]", isActive ? "text-cyan/60" : "text-lilac/15")}>
                    {item.code}
                  </span>
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="mt-7 flex items-center justify-between px-2.5">
          <p className="mono-label text-lilac/35">Modules</p>
          <span className="font-mono text-[8px] uppercase tracking-[0.16em] text-magenta/50">04 armed</span>
        </div>
        <nav className="mt-2.5 space-y-[3px]" aria-label="Security checks">
          {moduleNav.map((item) => {
            const isActive = pathname === "/scan/new" && activeModule === item.id;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={onNavigate}
                className={classNames(
                  "group flex h-9 items-center gap-3 border-l border-transparent px-2.5 text-[11.5px] transition",
                  isActive
                    ? "border-magenta/70 bg-magenta/[0.045] text-paper"
                    : "text-lilac/45 hover:border-cyan/30 hover:bg-white/[0.02] hover:text-lilac/80",
                )}
              >
                <item.icon
                  className={classNames(
                    "size-[13px] transition",
                    isActive ? "text-magenta" : "text-lilac/25 group-hover:text-cyan/70",
                  )}
                  strokeWidth={1.7}
                />
                <span className="flex-1">{item.label}</span>
                <span className="font-mono text-[8px] text-lilac/20">{item.code}</span>
              </NavLink>
            );
          })}
        </nav>

        <div className="mt-7 border border-cyan/20 bg-[linear-gradient(135deg,rgba(0,229,255,0.06),rgba(139,92,246,0.03))] p-3">
          <div className="flex items-center gap-2">
            <FlaskConical className="size-3.5 text-cyan/85" />
            <span className="mono-label text-cyan/85">
              {backendOnline ? "Live backend" : "Backend offline"}
            </span>
          </div>
          <p className="mt-2 text-[10px] leading-relaxed text-lilac/45">
            {backendOnline
              ? "Connected to FastAPI & SQLite. Sample data is excluded from scan history."
              : "Start uvicorn on port 8000 to validate targets and persist scan records."}
          </p>
          <button
            type="button"
            onClick={() => {
              onNavigate?.();
              window.dispatchEvent(new CustomEvent("bhl:open-connection"));
            }}
            className="mt-3 inline-flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-cyan/70 transition hover:text-cyan"
          >
            Connection details <ChevronRight className="size-3" />
          </button>
        </div>

        <div className="mt-6 border-t border-[#142338] px-2.5 pb-5 pt-4">
          <div className="flex items-center justify-between gap-2">
            <span className="mono-label text-lilac/30">RAVENX 2026</span>
            <span className="font-mono text-[8px] tracking-[0.12em] text-lilac/25">PS-4</span>
          </div>
          <img
            src="/brand/ravenx-wordmark.png"
            alt="RAVENX - Her Power. Her Code. Her Future."
            className="mt-2.5 h-[24px] w-auto opacity-40"
          />
          <p className="mt-2 text-[9px] leading-relaxed text-lilac/25">
            Team Masala Dosa
            <br />
            GLA University, Mathura
          </p>
        </div>
      </div>
    </div>
  );
}

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [connectionOpen, setConnectionOpen] = useState(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const location = useLocation();
  const breadcrumb = useBreadcrumb();
  const utc = useUtcClock();

  useEffect(() => {
    const controller = new AbortController();
    void checkBackendHealth(controller.signal).then((res) => {
      if (!controller.signal.aborted) setBackendOnline(res.online);
    });
    return () => controller.abort();
  }, [location.pathname]);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname, location.search]);

  useEffect(() => {
    const openConnection = () => setConnectionOpen(true);
    window.addEventListener("bhl:open-connection", openConnection);
    return () => window.removeEventListener("bhl:open-connection", openConnection);
  }, []);

  return (
    <div className="min-h-screen">
      <div className="pointer-events-none fixed inset-x-0 top-0 z-[60] h-px bg-[linear-gradient(90deg,#00e5ff,rgba(139,92,246,0.7),#ff2d8d)] opacity-60" />

      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[248px] border-r border-[#172840] bg-[#040912] lg:block">
        <SidebarContent backendOnline={backendOnline} />
      </aside>

      {mobileOpen ? (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            type="button"
            aria-label="Close navigation"
            className="absolute inset-0 bg-[#01040a]/80 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="animate-fade-in absolute inset-y-0 left-0 w-[282px] border-r border-cyan/15 bg-[#040912]">
            <button
              type="button"
              onClick={() => setMobileOpen(false)}
              aria-label="Close menu"
              className="absolute right-3 top-4 z-10 border border-[#263b55] p-1.5 text-lilac/60"
            >
              <X className="size-4" />
            </button>
            <SidebarContent onNavigate={() => setMobileOpen(false)} backendOnline={backendOnline} />
          </aside>
        </div>
      ) : null}

      <div className="lg:pl-[248px]">
        <header className="sticky top-0 z-30 flex h-[58px] items-center justify-between gap-3 border-b border-[#172840] bg-[#050a13]/90 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation"
              className="border border-[#263b55] p-1.5 text-lilac/60 lg:hidden"
            >
              <Menu className="size-4" />
            </button>
            <div className="hidden items-center gap-2.5 sm:flex">
              <LogoMark size={18} />
              <span className="font-mono text-[8.5px] uppercase tracking-[0.18em] text-lilac/30">
                HQ / Node 07
              </span>
              <ChevronRight className="size-3 text-lilac/20" />
              <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-cyan/75">
                {breadcrumb}
              </span>
            </div>
            <div className="sm:hidden">
              <LogoLockup compact />
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2.5">
            <div className="hidden items-center gap-2 border-r border-[#1c2c42] pr-3 md:flex">
              <span className="size-[4px] rounded-full bg-good/80 soft-pulse" />
              <span className="font-mono text-[8.5px] uppercase tracking-[0.14em] text-lilac/35">
                UTC {utc}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setConnectionOpen(true)}
              className={classNames(
                "group inline-flex h-8 items-center gap-2 border px-2.5 transition",
                backendOnline
                  ? "border-good/25 bg-good/[0.045] hover:border-good/50 hover:bg-good/[0.09]"
                  : "border-magenta/25 bg-magenta/[0.045] hover:border-magenta/50 hover:bg-magenta/[0.09]",
              )}
              title={backendOnline ? "FastAPI backend connected" : "FastAPI backend offline or checking"}
            >
              <span
                className={classNames(
                  "soft-pulse size-[5px] rounded-full",
                  backendOnline ? "bg-good" : "bg-magenta",
                )}
              />
              <span
                className={classNames(
                  "font-mono text-[8.5px] uppercase tracking-[0.14em]",
                  backendOnline ? "text-good/90" : "text-magenta/90",
                )}
              >
                {backendOnline ? "API online" : "API offline"}
              </span>
            </button>
            <span className="hidden sm:block">
              <ButtonLink to="/scan/new" variant="gold" size="sm" icon={Plus}>
                New investigation
              </ButtonLink>
            </span>
            <span className="sm:hidden">
              <ButtonLink to="/scan/new" variant="gold" size="sm" aria-label="New investigation">
                <Plus className="size-4" />
              </ButtonLink>
            </span>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1480px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </main>

        <footer className="mx-auto flex w-full max-w-[1480px] flex-col items-start justify-between gap-2 border-t border-[#142338] px-4 py-5 sm:flex-row sm:items-center sm:px-6 lg:px-8">
          <div className="flex items-center gap-2">
            <CircleDot className="size-3 text-cyan/35" />
            <p className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-lilac/30">
              BUG HUNTER LAB / Don't just detect. Prove. Fix. Verify.
            </p>
          </div>
          <div className="flex items-center gap-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-lilac/25">
            <ShieldCheck className="size-3 text-good/50" />
            Authorized targets only / non-destructive
          </div>
        </footer>
      </div>

      <ConnectionModal open={connectionOpen} onClose={() => setConnectionOpen(false)} />
    </div>
  );
}
