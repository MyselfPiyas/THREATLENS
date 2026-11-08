export function getSupabaseEnvironmentStatus(): boolean {
  return Boolean(
    process.env.NEXT_PUBLIC_SUPABASE_URL?.trim() &&
      getSupabasePublicKey(),
  );
}

function getSupabasePublicKey(): string | undefined {
  return (
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY?.trim() ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY?.trim()
  );
}

export function getSupabasePublicCredentials(): { url: string; apiKey: string } {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const apiKey = getSupabasePublicKey();

  if (!url || !apiKey) {
    throw new Error("Supabase is not configured. Set NEXT_PUBLIC_SUPABASE_URL and a publishable key (or legacy anon key).");
  }

  return { url, apiKey };
}

