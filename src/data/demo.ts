import type { CheckId, Finding, Scan } from "../types";
import { createScanDraft, completeSeedScan, MODULE_INITIAL_STATE } from "../lib/scanFactory";
import { CHECK_ORDER } from "./checks";
import { buildFindingsForScan } from "./findings";

export interface DemoWorkspace {
  scans: Scan[];
  findings: Finding[];
  seededAt: string;
}

const ALL_CHECKS: CheckId[] = [...CHECK_ORDER];

function scanAt(
  meta: { id: string; sequence: number; label: string },
  checks: CheckId[],
  target: string,
  startedAt: string,
): Scan {
  const draft = createScanDraft(meta, { target, checks });
  return {
    ...draft,
    target,
    startedAt,
    logs: [
      {
        id: `${meta.id}-seed-log`,
        at: startedAt,
        level: "info",
        text: "Sample workspace loaded. This scan record is illustrative demo data.",
      },
    ],
  };
}

export function createDemoWorkspace(): DemoWorkspace {
  const now = Date.now();
  const days = (value: number) => new Date(now - value).toISOString();

  const completedMeta = [
    {
      id: "scan-1",
      sequence: 1,
      label: "Scan 01",
      startedAt: days(1000 * 60 * 60 * 26),
    },
    {
      id: "scan-2",
      sequence: 2,
      label: "Scan 02",
      startedAt: days(1000 * 60 * 60 * 4.5),
    },
    {
      id: "scan-3",
      sequence: 3,
      label: "Scan 03",
      startedAt: days(1000 * 60 * 47),
    },
  ];

  const completedScans: Scan[] = completedMeta.map((meta) => {
    const draft = scanAt(meta, ALL_CHECKS, "https://demo-app.example", meta.startedAt);
    const completed = completeSeedScan(draft);
    return {
      ...completed,
      logs: [
        ...completed.logs,
        {
          id: `${meta.id}-seed-done`,
          at: completed.completedAt ?? completed.startedAt,
          level: "success",
          text: "Sample scan completed. 9 illustrative findings recorded.",
        },
      ],
    };
  });

  const failedDraft = scanAt(
    { id: "scan-0", sequence: 0, label: "Scan 00" },
    ALL_CHECKS,
    "https://demo-app.example",
    days(1000 * 60 * 60 * 31),
  );
  const failedScan: Scan = {
    ...failedDraft,
    status: "failed",
    progress: 22,
    completedAt: new Date(new Date(failedDraft.startedAt).getTime() + 10_000).toISOString(),
    modules: {
      ...MODULE_INITIAL_STATE,
      headers: "failed",
      cookies: "skipped",
      paths: "skipped",
      injection: "skipped",
    },
    stages: failedDraft.stages.map((stage, index) => ({
      ...stage,
      status: index === 0 ? "done" : index === 1 ? "failed" : "pending",
    })),
    error:
      "Demo connectivity check timed out after 10.0s. No findings were recorded. This failed record is sample data.",
    logs: [
      {
        id: "scan-0-log-1",
        at: failedDraft.startedAt,
        level: "info",
        text: "Sample connectivity check started.",
      },
      {
        id: "scan-0-log-2",
        at: failedDraft.startedAt,
        level: "error",
        text: "Target did not answer the demo health probe. Scan stopped before module execution.",
      },
    ],
  };

  const findings: Finding[] = [];
  completedScans.forEach((scan) => {
    buildFindingsForScan(scan, ALL_CHECKS).forEach((finding) => {
      if (scan.sequence === 1 && finding.fingerprint === "header-xfo") {
        findings.push({
          ...finding,
          status: "open",
          verification: {
            status: "not-verified",
            before: finding.verification.before,
            note: "A rescan of this finding will re-check the observed evidence.",
          },
        });
      } else {
        findings.push(finding);
      }
    });
  });

  return {
    scans: [completedScans[2], completedScans[1], completedScans[0], failedScan],
    findings,
    seededAt: new Date().toISOString(),
  };
}
