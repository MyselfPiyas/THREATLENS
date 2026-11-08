import { ProfileForm } from "@/components/profile/profile-form";
import { getSupabaseEnvironmentStatus } from "@/lib/supabase/config";
import { createSupabaseServerClient } from "@/lib/supabase/server";
import { requireAuthenticatedUser } from "@/lib/supabase/require-user";

export default async function ProfilePage() {
  const user = await requireAuthenticatedUser();
  if (!getSupabaseEnvironmentStatus()) {
    return (
      <main className="mx-auto max-w-3xl px-5 py-12 sm:px-8">
        <div role="alert" className="rounded-xl border border-warning/25 bg-warning/5 p-5 text-sm leading-6 text-warning">
          Supabase is not configured. Add the project URL and publishable key to load your profile.
        </div>
      </main>
    );
  }

  let profile: { full_name: string | null; avatar_url: string | null } | null = null;
  let accountEmail: string | null = null;
  let loadError = false;
  try {
    const supabase = await createSupabaseServerClient();
    const { data: authData, error: authError } = await supabase.auth.getUser();
    if (authError) {
      loadError = true;
    } else {
      accountEmail = authData.user?.email ?? null;
    }
    const { data, error } = await supabase
      .from("profiles")
      .select("full_name,avatar_url")
      .eq("id", user.id)
      .maybeSingle();
    if (error) {
      loadError = true;
    } else if (data) {
      profile = data;
    }
  } catch {
    loadError = true;
  }

  return (
    <main className="mx-auto w-full max-w-[1100px] px-5 py-12 sm:px-8 lg:px-12">
      <div className="mb-8">
        <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-accent">Account</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-[-0.045em]">Your profile</h1>
        <p className="mt-3 text-sm leading-6 text-muted-foreground">Manage the profile information associated with your THREATLENS account.</p>
      </div>

      <section className="max-w-2xl rounded-2xl border border-border bg-panel/70 p-6 sm:p-8">
        {loadError ? (
          <div role="alert" className="rounded-xl border border-warning/25 bg-warning/5 p-4 text-sm leading-6 text-warning">
            Profile data could not be loaded. Confirm the THREATLENS database migration has been applied, then retry.
          </div>
        ) : profile ? (
          <>
            <div className="mb-7 rounded-xl border border-border bg-[#0b1220] px-4 py-3.5">
              <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">Account email</p>
              <p className="mt-2 break-all text-sm text-foreground">{accountEmail ?? "Email unavailable"}</p>
            </div>
            <ProfileForm fullName={profile.full_name ?? ""} avatarUrl={profile.avatar_url ?? ""} />
          </>
        ) : (
          <div role="status" className="rounded-xl border border-dashed border-border p-6 text-sm leading-6 text-muted-foreground">
            Your profile row has not appeared yet. Refresh in a moment; new accounts are provisioned by the database signup trigger.
          </div>
        )}
      </section>
    </main>
  );
}
