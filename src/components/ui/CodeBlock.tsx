import { useEffect, useState } from "react";
import { Check, Copy, TerminalSquare } from "lucide-react";
import { copyTextToClipboard } from "../../lib/clipboard";
import { classNames } from "../../lib/format";

function lineClass(line: string): string {
  if (/^(GET|POST|PUT|PATCH|DELETE) /.test(line)) return "text-paper";
  if (/^HTTP\/\d/.test(line)) return "text-gold";
  if (/^[A-Za-z-]+:/.test(line)) return "text-lilac/90";
  if (/^Set-Cookie:/.test(line)) return "text-lavender";
  if (/\[absent\]|\[redacted\]|OperationalError|500 Internal/.test(line)) return "text-critical";
  if (/^</.test(line)) return "text-lilac/40";
  return "text-lilac/65";
}

export function CodeBlock({
  code,
  title,
  meta,
  language,
  className,
  maxHeight = "max-h-[360px]",
  showCopy = true,
  lineNumbers = true,
  tone = "default",
}: {
  code: string;
  title?: string;
  meta?: string;
  language?: string;
  className?: string;
  maxHeight?: string;
  showCopy?: boolean;
  lineNumbers?: boolean;
  tone?: "default" | "danger" | "good" | "paper";
}) {
  const [copied, setCopied] = useState(false);
  const lines = code.split("\n");

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1600);
    return () => window.clearTimeout(timer);
  }, [copied]);

  async function onCopy() {
    const success = await copyTextToClipboard(code);
    if (success) setCopied(true);
  }

  return (
    <div
      className={classNames(
        "overflow-hidden rounded-[7px] border",
        tone === "danger"
          ? "border-critical/25 bg-[#0c0711]"
          : tone === "good"
            ? "border-good/20 bg-[#0a0f0d]"
            : tone === "paper"
              ? "border-[#241033]/15 bg-[#f1eafb]"
              : "border-lilac/[0.1] bg-[#0b0712]",
        className,
      )}
    >
      <div
        className={classNames(
          "flex items-center justify-between gap-3 border-b px-3.5 py-2.5",
          tone === "paper" ? "border-[#241033]/10" : "border-lilac/[0.08]",
        )}
      >
        <div className="flex min-w-0 items-center gap-2">
          <TerminalSquare
            className={classNames("size-3.5", tone === "paper" ? "text-[#552477]" : "text-lavender/60")}
            aria-hidden="true"
          />
          <span
            className={classNames(
              "truncate font-mono text-[10px] uppercase tracking-[0.12em]",
              tone === "paper" ? "text-[#552477]/80" : "text-lilac/50",
            )}
          >
            {title ?? "Observed response"}
          </span>
          {language ? (
            <span
              className={classNames(
                "rounded-[3px] border px-1.5 py-0.5 font-mono text-[8.5px] uppercase tracking-[0.1em]",
                tone === "paper"
                  ? "border-[#552477]/15 text-[#552477]/55"
                  : "border-white/10 text-lilac/35",
              )}
            >
              {language}
            </span>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          {meta ? (
            <span
              className={classNames(
                "hidden font-mono text-[9px] tracking-[0.06em] sm:block",
                tone === "paper" ? "text-[#552477]/45" : "text-lilac/30",
              )}
            >
              {meta}
            </span>
          ) : null}
          {showCopy ? (
            <button
              type="button"
              onClick={onCopy}
              aria-label="Copy code block"
              className={classNames(
                "inline-flex items-center gap-1.5 rounded-[4px] border px-2 py-1 text-[10px] transition",
                tone === "paper"
                  ? "border-[#552477]/15 text-[#552477]/70 hover:bg-[#552477]/[0.06]"
                  : "border-white/10 text-lilac/45 hover:border-white/20 hover:text-lilac",
              )}
            >
              {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
              {copied ? "Copied" : "Copy"}
            </button>
          ) : null}
        </div>
      </div>
      <div className={classNames("overflow-auto", maxHeight)}>
        <pre className="min-w-max px-0 py-3 font-mono text-[11.5px] leading-[1.9]">
          {lines.map((line, index) => (
            <div key={`${index}-${line.slice(0, 12)}`} className="flex min-w-full">
              {lineNumbers ? (
                <span
                  className={classNames(
                    "w-10 shrink-0 select-none pr-3 text-right text-[10px]",
                    tone === "paper" ? "text-[#552477]/25" : "text-lilac/20",
                  )}
                >
                  {String(index + 1).padStart(2, "0")}
                </span>
              ) : null}
              <span
                className={classNames(
                  "whitespace-pre pr-5",
                  tone === "paper" ? "text-[#241033]/85" : lineClass(line),
                )}
              >
                {line || " "}
              </span>
            </div>
          ))}
        </pre>
      </div>
    </div>
  );
}
