import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  compact = false,
}: {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div
      className={
        compact
          ? "flex flex-col items-center justify-center px-6 py-10 text-center"
          : "flex flex-col items-center justify-center px-6 py-16 text-center"
      }
    >
      <div className="flex size-10 items-center justify-center rounded-[8px] border border-lilac/10 bg-white/[0.025]">
        <Icon className="size-5 text-lilac/40" />
      </div>
      <p className="mt-4 text-[14px] font-medium text-paper">{title}</p>
      {description ? (
        <p className="mt-1.5 max-w-sm text-[12px] leading-relaxed text-lilac/45">{description}</p>
      ) : null}
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  );
}
