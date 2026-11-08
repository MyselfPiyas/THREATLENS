"use client";

import { useCallback, useState } from "react";
import { createSupabaseBrowserClient } from "@/lib/supabase/client";
import { analyzeSecurityHeaders, analyzeTls } from "@/services/api-client";
import type { SecurityHeadersResult, TlsResult } from "@/types/api";

export function useTlsAnalysis() {
  const [tls, setTls] = useState<TlsResult | null>(null);
  const [headers, setHeaders] = useState<SecurityHeadersResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const analyze = useCallback(async (url: string, scanId?: string) => {
    setBusy(true); setError(null);
    try {
      const { data, error: sessionError } = await createSupabaseBrowserClient().auth.getSession();
      if (sessionError || !data.session?.access_token) throw new Error("Your session has expired. Sign in again before analyzing TLS.");
      const [tlsResult, headerResult] = await Promise.all([analyzeTls(url, data.session.access_token, scanId), analyzeSecurityHeaders(url, data.session.access_token, scanId)]);
      setTls(tlsResult); setHeaders(headerResult);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "TLS analysis could not be completed."); }
    finally { setBusy(false); }
  }, []);
  return { tls, headers, busy, error, analyze };
}
