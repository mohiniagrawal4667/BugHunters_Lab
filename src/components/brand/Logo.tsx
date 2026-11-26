import { Link } from "react-router-dom";

export function LogoMark({ size = 34 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      className="shrink-0"
    >
      <defs>
        <linearGradient id="bhl-mark" x1="7" y1="3" x2="34" y2="37" gradientUnits="userSpaceOnUse">
          <stop stopColor="#62E6FF" />
          <stop offset="0.5" stopColor="#8B5CF6" />
          <stop offset="1" stopColor="#FF2D8D" />
        </linearGradient>
      </defs>
      <path
        d="M20 2.5 35.5 10v20L20 37.5 4.5 30V10L20 2.5Z"
        stroke="url(#bhl-mark)"
        strokeWidth="1.2"
      />
      <path
        d="M12.2 13.5 20 9.8l7.8 3.7-2.4 7.1L20 30.2l-5.4-9.6-2.4-7.1Z"
        fill="rgba(0,229,255,0.055)"
        stroke="url(#bhl-mark)"
        strokeWidth="1.1"
      />
      <path d="M15.4 18.3h9.2" stroke="#00E5FF" strokeWidth="1" strokeLinecap="round" />
      <circle cx="20" cy="18.3" r="2.2" stroke="#FF2D8D" strokeWidth="1.1" />
      <circle cx="20" cy="18.3" r="0.75" fill="#FF2D8D" />
      <path d="M12.6 25.4h14.8" stroke="url(#bhl-mark)" strokeWidth="1" strokeLinecap="round" opacity="0.6" />
    </svg>
  );
}

export function LogoLockup({ compact = false }: { compact?: boolean }) {
  return (
    <Link to="/" className="group flex items-center gap-3" aria-label="BUG HUNTER LAB overview">
      <span className="relative">
        <span className="absolute inset-0 blur-lg transition group-hover:blur-xl" style={{ background: "radial-gradient(circle, rgba(0,229,255,0.22), transparent 70%)" }} />
        <LogoMark size={compact ? 30 : 34} />
      </span>
      <span className="flex min-w-0 flex-col">
        <span className="truncate font-display text-[13px] font-semibold leading-none tracking-[0.16em] text-paper uppercase">
          Bug Hunter Lab
        </span>
        <span className="mt-1.5 font-mono text-[8px] uppercase tracking-[0.22em] text-lilac/45">
          Forensic scanner / RAVENX
        </span>
      </span>
    </Link>
  );
}
