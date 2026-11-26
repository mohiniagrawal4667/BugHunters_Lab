export type Severity = "critical" | "high" | "medium" | "low";
export type Confidence = "high" | "medium" | "low";
export type FindingStatus = "open" | "resolved" | "pending";
export type CheckId = "headers" | "cookies" | "paths" | "injection";
export type ScanStatus = "running" | "completed" | "failed" | "cancelled";
export type StageStatus = "pending" | "active" | "done" | "failed";
export type ModuleState = "idle" | "queued" | "running" | "done" | "skipped" | "failed";

export interface CheckDefinition {
  id: CheckId;
  index: string;
  name: string;
  shortName: string;
  summary: string;
  inspects: string[];
  evidence: string;
}

export interface AuthorizedTarget {
  url: string;
  origin: string;
  label: string;
  environment: string;
  note: string;
}

export interface ScanStage {
  id: string;
  label: string;
  detail: string;
  status: StageStatus;
  durationMs: number;
}

export interface ScanLogLine {
  id: string;
  at: string;
  level: "info" | "success" | "warn" | "error";
  text: string;
}

export interface Scan {
  id: string;
  sequence: number;
  label: string;
  target: string;
  checks: CheckId[];
  status: ScanStatus;
  startedAt: string;
  completedAt?: string;
  progress: number;
  currentStageId?: string;
  stages: ScanStage[];
  modules: Record<CheckId, ModuleState>;
  logs: ScanLogLine[];
  mode: "demo" | "live";
  dataSource: "sample" | "live";
  rescanOfFindingId?: string;
  verification?: VerificationSummary;
  error?: string;
  requestCount: number;
  totalChecks: number;
}

export interface VerificationSummary {
  findingId: string;
  findingTitle: string;
  outcome: "resolved" | "still-present";
  before: string;
  after: string;
  note: string;
}

export interface EvidenceCheck {
  label: string;
  value: string;
  expected: string;
  state: "pass" | "fail" | "warn";
}

export interface EvidenceComparisonRow {
  signal: string;
  baseline: string;
  observed: string;
  verdict: "pass" | "fail" | "warn" | "info";
  note?: string;
}

export interface FindingEvidence {
  request: string;
  response: string;
  baseline?: string;
  note?: string;
  checks?: EvidenceCheck[];
  comparison?: EvidenceComparisonRow[];
}

export interface VerificationState {
  status: "not-verified" | "verified-resolved" | "verified-open";
  before: string;
  after?: string;
  checkedAt?: string;
  scanId?: string;
  note?: string;
}

export interface FindingReference {
  label: string;
  value: string;
}

export interface Finding {
  id: string;
  fingerprint: string;
  scanId: string;
  title: string;
  category: CheckId;
  categoryLabel: string;
  moduleName: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  targetPath: string;
  detectedAt: string;
  summary: string;
  impact: string;
  severityRationale: string;
  confidenceRationale: string;
  evidence: FindingEvidence;
  remediation: string[];
  fixSnippet?: string;
  fixLanguage?: string;
  references: FindingReference[];
  verification: VerificationState;
  sample: boolean;
  rescanCount: number;
}

export interface ScanInput {
  target: string;
  checks: CheckId[];
  rescanOfFindingId?: string;
}

export interface ScanDraftMeta {
  id: string;
  sequence: number;
  label: string;
}

export interface ScanHandlers {
  onProgress: (scan: Scan) => void;
}

export interface ScanRunResult {
  findings: Finding[];
  verification?: VerificationSummary;
  updatedFinding?: Pick<Finding, "id" | "status" | "verification" | "rescanCount">;
}
