import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { classNames } from "../../lib/format";

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = "md",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg";
}) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const timer = window.setTimeout(() => closeRef.current?.focus(), 30);

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);

    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [onClose, open]);

  if (!open) return null;

  return createPortal(
    <div
      className="fixed inset-0 z-[90] flex items-end justify-center bg-[#08040d]/80 p-0 backdrop-blur-[3px] sm:items-center sm:p-6"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        aria-describedby={description ? "modal-description" : undefined}
        className={classNames(
          "animate-fade-up max-h-[92vh] w-full overflow-hidden rounded-t-[12px] border border-lilac/15 bg-[#180e26] shadow-[0_30px_120px_rgba(0,0,0,0.55)] sm:rounded-[10px]",
          size === "sm" ? "sm:max-w-md" : size === "lg" ? "sm:max-w-3xl" : "sm:max-w-xl",
        )}
      >
        <div className="flex items-start justify-between gap-4 border-b border-lilac/10 px-5 py-4 sm:px-6">
          <div>
            <h2 id="modal-title" className="text-[16px] font-semibold tracking-[-0.01em] text-paper">
              {title}
            </h2>
            {description ? (
              <p id="modal-description" className="mt-1 text-[12px] leading-relaxed text-lilac/50">
                {description}
              </p>
            ) : null}
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-[5px] border border-white/10 p-1.5 text-lilac/50 transition hover:border-white/20 hover:text-paper"
          >
            <X className="size-4" />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto px-5 py-5 sm:px-6">{children}</div>
        {footer ? (
          <div className="flex flex-wrap items-center justify-end gap-2 border-t border-lilac/10 bg-white/[0.015] px-5 py-3.5 sm:px-6">
            {footer}
          </div>
        ) : null}
      </div>
    </div>,
    document.body,
  );
}
