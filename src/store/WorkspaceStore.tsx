import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { CheckId, Finding, Scan } from "../types";
import {
  createLiveScanOnBackend,
  fetchFindingsFromBackend,
  fetchScansFromBackend,
} from "../services/api";

const LEGACY_DEMO_STORAGE_KEY = "bug-hunter-lab.workspace.v1";

export interface LiveScanStartInput {
  target: string;
  checks: CheckId[];
  authorized: boolean;
}

interface WorkspaceContextValue {
  scans: Scan[];
  findings: Finding[];
  ready: boolean;
  loading: boolean;
  backendError: string | null;
  refreshWorkspace: () => Promise<void>;
  startLiveScan: (input: LiveScanStartInput) => Promise<{ ok: boolean; scanId?: string; scan?: Scan; error?: string }>;
  cancelScan: (scanId: string) => void;
  rescanFinding: (findingId: string) => { ok: boolean; scanId?: string; error?: string };
  getScan: (scanId: string) => Scan | undefined;
  getFinding: (findingId: string) => Finding | undefined;
  getFindingsForScan: (scanId: string) => Finding[];
  latestPrimaryScan: Scan | undefined;
  isRunning: (scanId: string) => boolean;
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [ready, setReady] = useState(false);
  const [backendError, setBackendError] = useState<string | null>(null);

  const refreshWorkspace = useCallback(async () => {
    setLoading(true);
    try {
      const [remoteScans, remoteFindings] = await Promise.all([
        fetchScansFromBackend(),
        fetchFindingsFromBackend(),
      ]);
      // Defensive filter: never mix sample records into the real workspace history.
      setScans(remoteScans.filter((item) => item.dataSource !== "sample"));
      setFindings(remoteFindings.filter((item) => !item.sample));
      setBackendError(null);
    } catch (error) {
      setScans([]);
      setFindings([]);
      setBackendError(
        error instanceof Error
          ? error.message
          : "Cannot reach the FastAPI backend to load scan history.",
      );
    } finally {
      setLoading(false);
      setReady(true);
    }
  }, []);

  useEffect(() => {
    // Clear legacy Phase 1 demo localStorage cache so sample data never bleeds into real history.
    try {
      window.localStorage.removeItem(LEGACY_DEMO_STORAGE_KEY);
    } catch {
      // Ignore storage restrictions.
    }
    void refreshWorkspace();
  }, [refreshWorkspace]);

  const startLiveScan = useCallback(
    async (input: LiveScanStartInput) => {
      if (!input.authorized) {
        return {
          ok: false,
          error: "Confirm that you own or have explicit authorization to test this target.",
        };
      }
      if (input.checks.length === 0) {
        return {
          ok: false,
          error: "Select at least one check before starting a scan.",
        };
      }

      const result = await createLiveScanOnBackend(
        input.target,
        input.checks,
        input.authorized,
      );
      if (!result.ok || !result.scan) {
        return {
          ok: false,
          error: result.error ?? "Scan could not be executed.",
        };
      }

      await refreshWorkspace();
      return {
        ok: true,
        scanId: result.scan.id,
        scan: result.scan,
      };
    },
    [refreshWorkspace],
  );

  const cancelScan = useCallback((_scanId: string) => {
    // Live baseline scans execute synchronously on the backend in the pre-Phase-3 flow.
  }, []);

  const rescanFinding = useCallback((_findingId: string) => {
    return {
      ok: false,
      error: "Finding-level verification rescans require Phase 3/6 live scanner modules.",
    };
  }, []);

  const getScan = useCallback(
    (scanId: string) => scans.find((scan) => scan.id === scanId),
    [scans],
  );

  const getFinding = useCallback(
    (findingId: string) => findings.find((finding) => finding.id === findingId),
    [findings],
  );

  const getFindingsForScan = useCallback(
    (scanId: string) => findings.filter((finding) => finding.scanId === scanId),
    [findings],
  );

  const latestPrimaryScan = useMemo(
    () =>
      [...scans]
        .filter((scan) => scan.status === "completed" && !scan.rescanOfFindingId)
        .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())[0],
    [scans],
  );

  const isRunning = useCallback(
    (scanId: string) => scans.some((scan) => scan.id === scanId && scan.status === "running"),
    [scans],
  );

  const value: WorkspaceContextValue = {
    scans,
    findings,
    ready,
    loading,
    backendError,
    refreshWorkspace,
    startLiveScan,
    cancelScan,
    rescanFinding,
    getScan,
    getFinding,
    getFindingsForScan,
    latestPrimaryScan,
    isRunning,
  };

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceContextValue {
  const context = useContext(WorkspaceContext);
  if (!context) throw new Error("useWorkspace must be used inside WorkspaceProvider");
  return context;
}
