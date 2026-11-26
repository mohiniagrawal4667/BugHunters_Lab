import type {
  CheckId,
  ModuleState,
  Scan,
  ScanDraftMeta,
  ScanInput,
  ScanStage,
} from "../types";
import { CHECK_BY_ID, CHECK_ORDER } from "../data/checks";

export const MODULE_INITIAL_STATE: Record<CheckId, ModuleState> = {
  headers: "idle",
  cookies: "idle",
  paths: "idle",
  injection: "idle",
};

interface PlanStep {
  id: string;
  label: string;
  detail: string;
  durationMs: number;
}

const CHECK_STAGE_COPY: Record<CheckId, { label: string; detail: string }> = {
  headers: {
    label: "Inspecting HTTP headers",
    detail: "Reading security headers from the authorized response.",
  },
  cookies: {
    label: "Analyzing cookie flags",
    detail: "Parsing Set-Cookie attributes: Secure, HttpOnly and SameSite.",
  },
  paths: {
    label: "Checking exposed paths",
    detail: "Comparing predefined paths against the baseline not-found response.",
  },
  injection: {
    label: "Testing injection indicators",
    detail: "Sending a controlled probe and comparing it with a normal baseline input.",
  },
};

export function buildStagePlan(checks: CheckId[], isRescan: boolean): PlanStep[] {
  if (isRescan) {
    return [
      {
        id: "validate",
        label: "Validating authorized target",
        detail: "Re-checking the target against the allowlist.",
        durationMs: 700,
      },
      {
        id: "recheck",
        label: "Re-checking observed evidence",
        detail: "Repeating only the module that produced the original finding.",
        durationMs: 1500,
      },
      {
        id: "compare",
        label: "Comparing with prior evidence",
        detail: "The previous observation is compared with the new response.",
        durationMs: 1000,
      },
      {
        id: "update",
        label: "Updating verification status",
        detail: "The finding is marked resolved or verified as still present.",
        durationMs: 800,
      },
    ];
  }

  const moduleStages: PlanStep[] = checks.map((check) => ({
    id: `check-${check}`,
    label: CHECK_STAGE_COPY[check].label,
    detail: CHECK_STAGE_COPY[check].detail,
    durationMs: 1250,
  }));

  return [
    {
      id: "validate",
      label: "Validating authorized target",
      detail: "The allowlist gate runs before any request leaves the scanner.",
      durationMs: 850,
    },
    ...moduleStages,
    {
      id: "evidence",
      label: "Processing evidence",
      detail: "Grouping raw observations and keeping evidence separate from interpretation.",
      durationMs: 1050,
    },
    {
      id: "findings",
      label: "Generating findings",
      detail: "Assigning severity, confidence and a specific remediation to each observation.",
      durationMs: 850,
    },
  ];
}

export function stagesFromPlan(plan: PlanStep[]): ScanStage[] {
  return plan.map((step) => ({
    ...step,
    status: "pending" as const,
  }));
}

export function createScanDraft(meta: ScanDraftMeta, input: ScanInput): Scan {
  const isRescan = Boolean(input.rescanOfFindingId);
  const plan = buildStagePlan(input.checks, isRescan);
  const selected = new Set(input.checks);
  const modules = { ...MODULE_INITIAL_STATE };
  CHECK_ORDER.forEach((check) => {
    modules[check] = selected.has(check) ? "queued" : "skipped";
  });

  const now = new Date().toISOString();

  return {
    id: meta.id,
    sequence: meta.sequence,
    label: meta.label,
    target: input.target,
    checks: input.checks,
    status: "running",
    startedAt: now,
    progress: 0,
    stages: stagesFromPlan(plan),
    modules,
    logs: [
      {
        id: `${meta.id}-log-0`,
        at: now,
        level: "info",
        text: "Demo run queued. No network requests will be sent from this browser.",
      },
    ],
    mode: "demo",
    dataSource: "sample",
    rescanOfFindingId: input.rescanOfFindingId,
    requestCount: 0,
    totalChecks: input.checks.length,
  };
}

export function completeSeedScan(scan: Scan): Scan {
  const total = scan.stages.reduce((sum, stage) => sum + stage.durationMs, 0);
  const completed = new Date(new Date(scan.startedAt).getTime() + total).toISOString();
  return {
    ...scan,
    status: "completed",
    progress: 100,
    completedAt: completed,
    stages: scan.stages.map((stage) => ({ ...stage, status: "done" })),
    modules: Object.fromEntries(
      CHECK_ORDER.map((check) => [check, scan.checks.includes(check) ? "done" : "skipped"]),
    ) as Record<CheckId, ModuleState>,
  };
}

export function stageIndexForCheck(check: CheckId): string {
  return CHECK_BY_ID[check].index;
}

export function plannedDuration(checks: CheckId[], isRescan = false): number {
  return buildStagePlan(checks, isRescan).reduce((sum, stage) => sum + stage.durationMs, 0);
}
