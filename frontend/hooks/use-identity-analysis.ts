"use client";

import { useCallback, useState } from "react";
import { createSupabaseBrowserClient } from "@/lib/supabase/client";
import { analyzeWebsiteIdentity } from "@/services/api-client";
import type { IdentityResult } from "@/types/api";

export function useIdentityAnalysis() {
  const [result, setResult] = useState<IdentityResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const analyze = useCallback(async (url: string, scanId?: string) => {
    setBusy(true); setError(null);
    try {
      const { data, error: sessionError } = await createSupabaseBrowserClient().auth.getSession();
      if (sessionError || !data.session?.access_token) throw new Error("Your session has expired. Sign in again before analyzing identity.");
      setResult(await analyzeWebsiteIdentity(url, data.session.access_token, scanId));
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Identity analysis could not be completed."); }
    finally { setBusy(false); }
  }, []);
  return { result, busy, error, analyze };
}
