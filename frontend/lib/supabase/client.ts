"use client";

import { createBrowserClient } from "@supabase/ssr";
import { getSupabasePublicCredentials } from "@/lib/supabase/config";

export function createSupabaseBrowserClient() {
  const { url, apiKey } = getSupabasePublicCredentials();
  return createBrowserClient(url, apiKey);
}

