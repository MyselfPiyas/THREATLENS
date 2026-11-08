"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createSupabaseBrowserClient } from "@/lib/supabase/client";
import { getUrlScanReport, getUrlScanStatus, submitUrlScan } from "@/services/api-client";
import type { ScanReport, UrlScanStatus } from "@/types/api";

export type UrlScanFlow = {
  status: "idle" | "authenticating" | UrlScanStatus | "error";
  scanId: string | null;
  report: ScanReport | null;
  error: string | null;
};

const INITIAL_FLOW: UrlScanFlow = { status: "idle", scanId: null, report: null, error: null };

export function useUrlScan() {
  const [flow, setFlow] = useState<UrlScanFlow>(INITIAL_FLOW);
  const activeRun = useRef(0);

  useEffect(() => () => { activeRun.current += 1; }, []);

  const reset = useCallback(() => {
    activeRun.current += 1;
    setFlow(INITIAL_FLOW);
  }, []);

  const submit = useCallback(async (url: string) => {
    const runId = ++activeRun.current;
    let scanId: string | null = null;
    setFlow({ ...INITIAL_FLOW, status: "authenticating" });
    try {
      const supabase = createSupabaseBrowserClient();
      const { data, error } = await supabase.auth.getSession();
      const accessToken = data.session?.access_token;
      if (error || !accessToken) throw new Error("Your session has expired. Sign in again before starting a scan.");

      const accepted = await submitUrlScan(url, accessToken);
      scanId = accepted.scan_id;
      if (activeRun.current !== runId) return;
      setFlow({ status: "queued", scanId: accepted.scan_id, report: null, error: null });

      for (let attempt = 0; attempt < 90; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 1000));
        if (activeRun.current !== runId) return;
        const progress = await getUrlScanStatus(accepted.scan_id, accessToken);
        if (progress.status === "completed" || progress.status === "failed" || progress.status === "cancelled") {
          const report = await getUrlScanReport(accepted.scan_id, accessToken);
          if (activeRun.current === runId) {
            setFlow({ status: report.scan.status, scanId: accepted.scan_id, report, error: null });
          }
          return;
        }
        setFlow({ status: progress.status, scanId: accepted.scan_id, report: null, error: null });
      }
      if (activeRun.current === runId) {
        setFlow({ status: "error", scanId: accepted.scan_id, report: null, error: "This scan is taking longer than expected. You can check its progress in scan history." });
      }
    } catch (error) {
      if (activeRun.current === runId) {
        setFlow({ ...INITIAL_FLOW, status: "error", scanId, error: error instanceof Error ? error.message : "The scan could not be started." });
      }
    }
  }, []);

  return { flow, submit, reset };
}
