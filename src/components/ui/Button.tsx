import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Link, type LinkProps } from "react-router-dom";
import type { LucideIcon } from "lucide-react";
import { LoaderCircle } from "lucide-react";
import { classNames } from "../../lib/format";

type Variant = "primary" | "gold" | "secondary" | "ghost" | "danger" | "quiet";
type Size = "sm" | "md" | "lg";

const base =
  "inline-flex select-none items-center justify-center gap-2 rounded-[3px] font-mono font-medium uppercase tracking-[0.08em] transition-all duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 disabled:pointer-events-none disabled:border disabled:border-[#26384e] disabled:bg-[#101b2b] disabled:text-lilac/45 disabled:shadow-none";

const variants: Record<Variant, string> = {
  primary:
    "bg-cyan text-[#031018] shadow-[0_0_26px_rgba(0,229,255,0.14)] hover:bg-[#7af4ff] hover:shadow-[0_0_34px_rgba(0,229,255,0.22)] active:bg-[#00c8de]",
  gold:
    "bg-magenta text-white shadow-[0_0_28px_rgba(255,45,141,0.16)] hover:bg-[#ff5aa6] active:bg-[#e0257c]",
  secondary:
    "border border-cyan/20 bg-cyan/[0.035] text-paper hover:border-cyan/45 hover:bg-cyan/[0.07]",
  ghost:
    "text-lilac/75 hover:bg-cyan/[0.06] hover:text-cyan",
  danger:
    "border border-critical/35 bg-critical/[0.07] text-critical hover:border-critical/60 hover:bg-critical/[0.13]",
  quiet:
    "border border-[#2a3a50]/70 bg-transparent text-lilac/65 hover:border-cyan/30 hover:text-paper",
};

const sizes: Record<Size, string> = {
  sm: "h-8 px-3 text-[10px]",
  md: "h-10 px-4 text-[11px]",
  lg: "h-11 px-5 text-[12px]",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  icon?: LucideIcon;
  iconRight?: LucideIcon;
  loading?: boolean;
  children?: ReactNode;
}

export function buttonClassName(variant: Variant = "secondary", size: Size = "md") {
  return classNames(base, variants[variant], sizes[size]);
}

export function Button({
  variant = "secondary",
  size = "md",
  icon: Icon,
  iconRight: IconRight,
  loading = false,
  className,
  children,
  disabled,
  ...props
}: ButtonProps) {
  return (
    <button
      className={classNames(buttonClassName(variant, size), className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
      ) : Icon ? (
        <Icon className="size-4" aria-hidden="true" />
      ) : null}
      {children}
      {IconRight ? <IconRight className="size-4" aria-hidden="true" /> : null}
    </button>
  );
}

export function ButtonLink({
  variant = "secondary",
  size = "md",
  icon: Icon,
  iconRight: IconRight,
  className,
  children,
  ...props
}: LinkProps & { variant?: Variant; size?: Size; icon?: LucideIcon; iconRight?: LucideIcon }) {
  return (
    <Link className={classNames(buttonClassName(variant, size), className)} {...props}>
      {Icon ? <Icon className="size-4" aria-hidden="true" /> : null}
      {children}
      {IconRight ? <IconRight className="size-4" aria-hidden="true" /> : null}
    </Link>
  );
}
