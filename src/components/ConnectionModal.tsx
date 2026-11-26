import { useEffect, useState } from "react";
import { Check, Database, PlugZap, RefreshCw, ServerOff, ShieldCheck } from "lucide-react";
import { Modal } from "./ui/Modal";
import { Button } from "./ui/Button";
import { CodeBlock } from "./ui/CodeBlock";
import { useWorkspace } from "../store/WorkspaceStore";
import { API_CONTRACT, API_DISPLAY_URL, checkBackendHealth } from "../services/api";

export function ConnectionModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { refreshWorkspace, scans } = useWorkspace();
  const [health, setHealth] = useState<{
    online: boolean;
    database?: string;
    checked: boolean;
  }>({
    online: false,
    checked: false,
  });

  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    void checkBackendHealth(controller.signal).then((res) => {
      if (!controller.signal.aborted) {
        setHealth({ online: res.online, database: res.database, checked: true });
      }
    });
    return () => controller.abort();
  }, [open]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Backend connection & database"
      description="Live status of the FastAPI target validation API and SQLite scan history."
      size="lg"
      footer={
        <>
          <Button
            variant="quiet"
            size="sm"
            icon={RefreshCw}
            onClick={() => {
              void refreshWorkspace();
              void checkBackendHealth().then((res) =>
                setHealth({ online: res.online, database: res.database, checked: true }),
              );
            }}
          >
            Refresh status
          </Button>
          <Button variant="primary" size="sm" onClick={onClose}>
            Done
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <div
          className={
            health.online
              ? "flex items-start gap-3 rounded-[3px] border border-good/25 bg-good/[0.06] p-3.5"
              : "flex items-start gap-3 rounded-[3px] border border-critical/25 bg-critical/[0.06] p-3.5"
          }
        >
          {health.online ? (
            <ShieldCheck className="mt-0.5 size-4 shrink-0 text-good" />
          ) : (
            <ServerOff className="mt-0.5 size-4 shrink-0 text-critical" />
          )}
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-[12.5px] font-medium text-paper">
                {health.online ? "FastAPI backend connected" : "FastAPI backend offline"}
              </p>
              <span className="rounded-[3px] border border-white/15 px-1.5 py-0.5 font-mono text-[8.5px] uppercase tracking-[0.12em] text-lilac/75">
                {health.online ? "SQLite persistence active" : "No connection"}
              </span>
            </div>
            <p className="mt-1 text-[12px] leading-relaxed text-lilac/55">
              {health.online
                ? "Target validation and scan history are backed by FastAPI and SQLite. Sample demo records are excluded from real history."
                : "Start the FastAPI server on port 8000 to validate targets and persist scan history."}
            </p>
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-[3px] border border-[#1a2b42] bg-[#07101d] p-3.5">
            <div className="flex items-center gap-2">
              <PlugZap className="size-3.5 text-cyan" />
              <p className="mono-label text-lilac/45">Backend API</p>
            </div>
            <p className="mt-2 text-[12.5px] text-paper">
              {health.online ? "Online" : "Offline"}
            </p>
            <p className="mt-1 font-mono text-[10px] text-lilac/40">API base: {API_DISPLAY_URL}</p>
          </div>
          <div className="rounded-[3px] border border-[#1a2b42] bg-[#07101d] p-3.5">
            <div className="flex items-center gap-2">
              <Database className="size-3.5 text-good" />
              <p className="mono-label text-lilac/45">Database records</p>
            </div>
            <p className="mt-2 text-[12.5px] text-paper">
              {scans.length} persisted scan{scans.length === 1 ? "" : "s"}
            </p>
            <p className="mt-1 font-mono text-[10px] text-lilac/40">
              Engine: {health.database ?? "sqlite"}
            </p>
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="size-3.5 text-lilac/50" />
              <p className="mono-label text-lilac/45">Active FastAPI endpoints</p>
            </div>
          </div>
          <div className="mt-2.5 overflow-hidden rounded-[2px] border border-[#1a2b42] bg-[#050b14]">
            {API_CONTRACT.map((endpoint, index) => (
              <div
                key={endpoint.path}
                className={
                  index === 0
                    ? "grid grid-cols-[52px_1fr] gap-3 px-3 py-3"
                    : "grid grid-cols-[52px_1fr] gap-3 border-t border-[#142338] px-3 py-2.5"
                }
              >
                <span className="font-mono text-[9px] uppercase tracking-[0.08em] text-gold/80">
                  {endpoint.method}
                </span>
                <div>
                  <p className="font-mono text-[10.5px] text-lilac/80">{endpoint.path}</p>
                  <p className="mt-0.5 text-[10.5px] text-lilac/35">{endpoint.purpose}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div>
          <p className="mono-label text-lilac/45">Run backend locally</p>
          <CodeBlock
            className="mt-2.5"
            title="PowerShell"
            code="python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload"
            showCopy={false}
            lineNumbers={false}
            maxHeight="max-h-none"
          />
        </div>

        <div className="flex items-start gap-2 text-[11px] leading-relaxed text-lilac/40">
          <Check className="mt-0.5 size-3.5 shrink-0 text-good/70" />
          All scan records displayed in Case Records and Investigation HQ come directly from SQLite via{" "}
          <span className="font-mono text-lilac/60">GET /api/scans</span>.
        </div>
      </div>
    </Modal>
  );
}
