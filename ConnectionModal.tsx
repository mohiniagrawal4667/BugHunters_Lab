import { useState } from "react";
import { Check, Database, PlugZap, RotateCcw, ServerOff, ShieldCheck } from "lucide-react";
import { Modal } from "./ui/Modal";
import { Button } from "./ui/Button";
import { CodeBlock } from "./ui/CodeBlock";
import { useToast } from "./ui/Toast";
import { useWorkspace } from "../store/WorkspaceStore";
import { API_BASE_URL, API_CONTRACT, scannerApi } from "../services/api";

export function ConnectionModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { resetDemoWorkspace } = useWorkspace();
  const { push } = useToast();
  const [confirmReset, setConfirmReset] = useState(false);

  function resetWorkspace() {
    resetDemoWorkspace();
    setConfirmReset(false);
    onClose();
    push({
      tone: "success",
      title: "Sample workspace restored",
      description: "All local scans were replaced with the original demo records.",
    });
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Connection & data source"
      description="The frontend is ready for the FastAPI backend, but this build runs on a local demo adapter."
      size="lg"
      footer={
        <>
          {confirmReset ? (
            <>
              <span className="mr-auto text-[10.5px] text-[#65707d]">Replace all local scans and findings with the original sample workspace?</span>
              <Button variant="quiet" size="sm" onClick={() => setConfirmReset(false)}>
                Cancel
              </Button>
              <Button variant="danger" size="sm" icon={RotateCcw} onClick={resetWorkspace}>
                Reset workspace
              </Button>
            </>
          ) : (
            <>
              <Button variant="quiet" size="sm" onClick={() => setConfirmReset(true)}>
                Reset sample workspace
              </Button>
              <Button variant="primary" size="sm" onClick={onClose}>
                Done
              </Button>
            </>
          )}
        </>
      }
    >
      <div className="space-y-5">
        <div className="flex items-start gap-3 border-l-[3px] border-[#f52d8a] bg-[#f52d8a]/[0.04] px-3.5 py-3">
          <ServerOff className="mt-0.5 size-4 shrink-0 text-[#b41860]" />
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-[12px] font-medium text-[#101a2c]">Demo adapter active</p>
              <span className="border border-[#f52d8a]/30 px-1.5 py-0.5 font-mono text-[7.5px] uppercase tracking-[0.1em] text-[#b41860]">
                No network requests
              </span>
            </div>
            <p className="mt-1 text-[10.5px] leading-relaxed text-[#65707d]">
              Scans are simulated locally so the interface can be demonstrated. Every finding is labelled sample data. Nothing is sent to demo-app.example or any other target.
            </p>
          </div>
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          <div className="border border-[#d8d3c6] bg-white p-3.5">
            <div className="flex items-center gap-2">
              <PlugZap className="size-3.5 text-[#007e90]" />
              <p className="font-mono text-[8px] uppercase tracking-[0.13em] text-[#6c756f]">Adapter</p>
            </div>
            <p className="mt-2 text-[12px] text-[#101a2c]">{scannerApi.mode === "demo" ? "Local demo engine" : "FastAPI"}</p>
            <p className="mt-1 font-mono text-[9px] text-[#8a8578]">API base: {API_BASE_URL}</p>
          </div>
          <div className="border border-[#d8d3c6] bg-white p-3.5">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-3.5 text-[#0b7456]" />
              <p className="font-mono text-[8px] uppercase tracking-[0.13em] text-[#6c756f]">Allowlist gate</p>
            </div>
            <p className="mt-2 text-[12px] text-[#101a2c]">2 authorized origins</p>
            <p className="mt-1 font-mono text-[9px] text-[#8a8578]">demo-app.example / localhost:8000</p>
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="size-3.5 text-[#007e90]" />
              <p className="font-mono text-[8px] uppercase tracking-[0.13em] text-[#6c756f]">Proposed FastAPI surface</p>
            </div>
            <span className="font-mono text-[7.5px] uppercase tracking-[0.1em] text-[#a39c8d]">contract only</span>
          </div>
          <div className="mt-2.5 overflow-hidden border border-[#101a2c] bg-[#0b1424]">
            {API_CONTRACT.map((endpoint, index) => (
              <div
                key={endpoint.path}
                className={
                  index === 0
                    ? "grid grid-cols-[52px_1fr] gap-3 px-3 py-3"
                    : "grid grid-cols-[52px_1fr] gap-3 border-t border-white/10 px-3 py-2.5"
                }
              >
                <span className="font-mono text-[8px] uppercase tracking-[0.08em] text-[#8defff]">{endpoint.method}</span>
                <div>
                  <p className="font-mono text-[10px] text-[#f4f1e9]">{endpoint.path}</p>
                  <p className="mt-0.5 text-[9.5px] leading-relaxed text-[#8b96a3]">{endpoint.purpose}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div>
          <p className="font-mono text-[8px] uppercase tracking-[0.13em] text-[#6c756f]">Connect the backend later</p>
          <CodeBlock
            className="mt-2.5"
            title=".env.local"
            code={[
              "VITE_API_BASE_URL=http://127.0.0.1:8000",
              "",
              "# The demo adapter remains the default until the API",
              "# contract in src/services/api.ts is implemented.",
            ].join("\n")}
            showCopy={false}
            lineNumbers={false}
            maxHeight="max-h-none"
          />
        </div>

        <div className="flex items-start gap-2 text-[10px] leading-relaxed text-[#65707d]">
          <Check className="mt-0.5 size-3.5 shrink-0 text-[#0b7456]" />
          <span>
            The service boundary lives in <span className="font-mono text-[#101a2c]">src/services/api.ts</span>. PDF export, filtering and verification state are already driven by the same data model the backend will return.
          </span>
        </div>
      </div>
    </Modal>
  );
}
