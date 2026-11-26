import type { CheckId, Finding, Scan, ScanHandlers, ScanInput, ScanRunResult } from "../types";
import { RESCAN_SCENARIOS, applyRescanToFinding, buildFindingsForScan } from "../data/findings";
import { CHECK_BY_ID } from "../data/checks";

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException("Scan cancelled", "AbortError"));
      return;
    }
    const timer = globalThis.setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      globalThis.clearTimeout(timer);
      reject(new DOMException("Scan cancelled", "AbortError"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function appendLog(scan: Scan, level: "info" | "success" | "warn" | "error", text: string): Scan {
  return {
    ...scan,
    logs: [
      ...scan.logs,
      {
        id: `${scan.id}-log-${scan.logs.length}`,
        at: new Date().toISOString(),
        level,
        text,
      },
    ].slice(-32),
  };
}

function withStageStatus(
  scan: Scan,
  stageIndex: number,
  status: "active" | "done" | "failed",
): Scan {
  return {
    ...scan,
    stages: scan.stages.map((stage, index) => {
      if (index === stageIndex) return { ...stage, status };
      if (index < stageIndex) return { ...stage, status: "done" };
      return stage;
    }),
  };
}

function completeProgress(scan: Scan): Scan {
  return {
    ...scan,
    progress: 100,
    stages: scan.stages.map((stage) => ({ ...stage, status: "done" })),
    currentStageId: undefined,
  };
}

export interface DemoRunCallbacks extends ScanHandlers {
  onFindingUpdate?: (update: NonNullable<ScanRunResult["updatedFinding"]>) => void;
}

export interface DemoRunContext {
  rescanFinding?: Finding;
}

export async function runDemoScan(
  initialScan: Scan,
  input: ScanInput,
  context: DemoRunContext,
  callbacks: DemoRunCallbacks,
  signal: AbortSignal,
): Promise<ScanRunResult> {
  let scan = initialScan;
  const rescanFinding = context.rescanFinding;
  const isRescan = Boolean(rescanFinding);
  const totalStages = scan.stages.length;

  callbacks.onProgress(scan);
  await delay(280, signal);

  for (let index = 0; index < scan.stages.length; index += 1) {
    const stage = scan.stages[index];
    const baseProgress = Math.round((index / totalStages) * 100);

    scan = appendLog(
      scan,
      "info",
      isRescan ? `Demo check: ${stage.label.toLowerCase()}.` : `Demo step: ${stage.label.toLowerCase()}.`,
    );
    scan = {
      ...scan,
      currentStageId: stage.id,
      progress: Math.max(2, baseProgress),
      stages: withStageStatus(scan, index, "active").stages,
    };

    if (!isRescan && stage.id.startsWith("check-")) {
      const checkId = stage.id.replace("check-", "") as CheckId;
      scan = { ...scan, modules: { ...scan.modules, [checkId]: "running" } };
      callbacks.onProgress(scan);
      await delay(stage.durationMs, signal);

      const count = buildFindingsForScan(scan, [checkId]).length;
      scan = {
        ...scan,
        modules: { ...scan.modules, [checkId]: "done" },
        stages: scan.stages.map((item, itemIndex) =>
          itemIndex === index ? { ...item, status: "done" } : item,
        ),
        logs: [
          ...scan.logs,
          {
            id: `${scan.id}-log-${scan.logs.length}`,
            at: new Date().toISOString(),
            level: "success" as const,
            text: `${CHECK_BY_ID[checkId].name}: ${count} sample observation${count === 1 ? "" : "s"} prepared.`,
          },
        ].slice(-32),
      };
    } else if (isRescan && rescanFinding && stage.id === "recheck") {
      scan = {
        ...scan,
        modules: { ...scan.modules, [rescanFinding.category]: "running" },
        logs: [
          ...scan.logs,
          {
            id: `${scan.id}-log-${scan.logs.length}`,
            at: new Date().toISOString(),
            level: "info" as const,
            text: `${rescanFinding.moduleName}: re-checking "${rescanFinding.title}".`,
          },
        ].slice(-32),
      };
      callbacks.onProgress(scan);
      await delay(stage.durationMs, signal);
      scan = {
        ...scan,
        modules: { ...scan.modules, [rescanFinding.category]: "done" },
        stages: scan.stages.map((item, itemIndex) =>
          itemIndex === index ? { ...item, status: "done" } : item,
        ),
      };
    } else {
      callbacks.onProgress(scan);
      await delay(stage.durationMs, signal);
      scan = withStageStatus(scan, index, "done");
    }

    scan = {
      ...scan,
      progress: Math.round(((index + 1) / totalStages) * 100),
    };
    callbacks.onProgress(scan);
  }

  scan = completeProgress(scan);
  scan = appendLog(
    scan,
    "success",
    isRescan
      ? "Demo verification complete. The comparison is illustrative sample data."
      : "Demo evidence package built. Findings are illustrative sample data.",
  );

  if (isRescan && rescanFinding) {
    const scenario = RESCAN_SCENARIOS[rescanFinding.fingerprint] ?? {
      outcome: "still-present" as const,
      after: "Observed evidence unchanged.",
      note: "The demo rescan did not observe a change in the recorded evidence.",
    };
    const completedAt = new Date().toISOString();
    const completedScan: Scan = { ...scan, completedAt };
    const updatedFinding = applyRescanToFinding(rescanFinding, completedScan);

    return {
      findings: [],
      updatedFinding,
      verification: {
        findingId: rescanFinding.id,
        findingTitle: rescanFinding.title,
        outcome: scenario.outcome,
        before: rescanFinding.verification.before,
        after: scenario.after,
        note: scenario.note,
      },
    };
  }

  const findings = buildFindingsForScan(scan, input.checks);
  return { findings };
}
