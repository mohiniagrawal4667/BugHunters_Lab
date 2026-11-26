import { useState } from "react";
import type { Finding, Scan } from "../types";
import { downloadScanReport } from "../lib/pdf";
import { useToast } from "../components/ui/Toast";

export function useReportExport() {
  const { push } = useToast();
  const [exportingId, setExportingId] = useState<string | null>(null);

  async function exportReport(scan: Scan, findings: Finding[]) {
    if (exportingId) return;
    setExportingId(scan.id);
    try {
      // Let the button paint its loading state before the synchronous PDF build.
      await new Promise((resolve) => window.setTimeout(resolve, 80));
      const result = downloadScanReport(scan, findings);
      push({
        tone: "success",
        title: "PDF report downloaded",
        description: `${result.pageCount} pages · ${result.filename}`,
      });
    } catch (error) {
      push({
        tone: "error",
        title: "The PDF could not be generated",
        description:
          error instanceof Error ? error.message : "An unexpected error stopped the export.",
      });
    } finally {
      setExportingId(null);
    }
  }

  return { exportReport, exportingId };
}
