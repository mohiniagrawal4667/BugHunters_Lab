import { useEffect } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { WorkspaceProvider } from "./store/WorkspaceStore";
import { ToastProvider } from "./components/ui/Toast";
import { AppShell } from "./components/AppShell";
import { Dashboard } from "./pages/Dashboard";
import { NewScan } from "./pages/NewScan";
import { ScanProgress } from "./pages/ScanProgress";
import { Findings } from "./pages/Findings";
import { FindingDetail } from "./pages/FindingDetail";
import { Reports } from "./pages/Reports";
import { ReportDetail } from "./pages/ReportDetail";
import { NotFound } from "./pages/NotFound";

function ScrollToTop() {
  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" as ScrollBehavior });
  }, [pathname]);
  return null;
}

export default function App() {
  return (
    <BrowserRouter>
      <WorkspaceProvider>
        <ToastProvider>
          <ScrollToTop />
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<Dashboard />} />
              <Route path="scan/new" element={<NewScan />} />
              <Route path="scans/:scanId/progress" element={<ScanProgress />} />
              <Route path="findings" element={<Findings />} />
              <Route path="findings/:findingId" element={<FindingDetail />} />
              <Route path="reports" element={<Reports />} />
              <Route path="reports/:scanId" element={<ReportDetail />} />
              <Route path="dashboard" element={<Navigate to="/" replace />} />
              <Route path="*" element={<NotFound />} />
            </Route>
          </Routes>
        </ToastProvider>
      </WorkspaceProvider>
    </BrowserRouter>
  );
}
