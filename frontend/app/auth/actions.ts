"use server";

import { redirect } from "next/navigation";

import { getSupabaseEnvironmentStatus } from "@/lib/supabase/config";
import { getSafeRedirectPath } from "@/lib/supabase/safe-redirect";
import { createSupabaseServerClient } from "@/lib/supabase/server";
import { getSiteUrl } from "@/lib/supabase/site-url";
import type { AuthActionState } from "@/types/auth";

const INVALID_FORM: AuthActionState = { kind: "error", message: "Review the required fields and try again." };
const AUTH_NOT_CONFIGURED: AuthActionState = {
  kind: "error",
  message: "Authentication is not configured yet. Add the Supabase URL and publishable key to the frontend environment.",
};

function formText(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === "string" ? value : "";
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function isValidEmail(value: string): boolean {
  return value.length <= 320 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function authUnavailable(): AuthActionState {
  return {
    kind: "error",
    message: "Supabase Auth could not be reached. Check the project settings and try again.",
  };
}

function safeNext(formData: FormData): string {
  return getSafeRedirectPath(formText(formData, "next"));
}

export async function signInAction(
  _previousState: AuthActionState,
  formData: FormData,
): Promise<AuthActionState> {
  const email = normalizeEmail(formText(formData, "email"));
  const password = formText(formData, "password");
  if (!isValidEmail(email) || password.length < 1 || password.length > 128) {
    return INVALID_FORM;
  }
  if (!getSupabaseEnvironmentStatus()) {
    return AUTH_NOT_CONFIGURED;
  }

  let hasError = false;
  try {
    const supabase = await createSupabaseServerClient();
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    hasError = Boolean(error);
  } catch {
    return authUnavailable();
  }
  if (hasError) {
    return { kind: "error", message: "We couldn't sign you in with those details." };
  }

  redirect(safeNext(formData));
}

export async function signUpAction(
  _previousState: AuthActionState,
  formData: FormData,
): Promise<AuthActionState> {
  const fullName = formText(formData, "full_name").trim();
  const email = normalizeEmail(formText(formData, "email"));
  const password = formText(formData, "password");
  if (
    fullName.length < 2 ||
    fullName.length > 160 ||
    !isValidEmail(email) ||
    password.length < 12 ||
    password.length > 128
  ) {
    return INVALID_FORM;
  }
  if (!getSupabaseEnvironmentStatus()) {
    return AUTH_NOT_CONFIGURED;
  }

  let createdSession = false;
  try {
    const supabase = await createSupabaseServerClient();
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { full_name: fullName },
        emailRedirectTo: getSiteUrl() + "/auth/callback?next=%2Fdashboard",
      },
    });
    if (error) {
      return { kind: "error", message: "We couldn't create an account with those details." };
    }
    createdSession = Boolean(data.session);
  } catch {
    return authUnavailable();
  }

  if (createdSession) {
    redirect(safeNext(formData));
  }

  return {
    kind: "success",
    message: "Check your inbox for a confirmation link to finish creating your account.",
  };
}

export async function requestPasswordResetAction(
  _previousState: AuthActionState,
  formData: FormData,
): Promise<AuthActionState> {
  const email = normalizeEmail(formText(formData, "email"));
  if (!isValidEmail(email)) {
    return INVALID_FORM;
  }
  if (!getSupabaseEnvironmentStatus()) {
    return AUTH_NOT_CONFIGURED;
  }

  try {
    const supabase = await createSupabaseServerClient();
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: getSiteUrl() + "/auth/callback?next=%2Fauth%2Freset-password",
    });
    if (error) {
      return { kind: "error", message: "We couldn't send a reset link right now. Please try again shortly." };
    }
  } catch {
    return authUnavailable();
  }

  return {
    kind: "success",
    message: "If that address can receive a reset link, an email is on its way.",
  };
}

export async function resetPasswordAction(
  _previousState: AuthActionState,
  formData: FormData,
): Promise<AuthActionState> {
  const password = formText(formData, "password");
  const confirmation = formText(formData, "confirm_password");
  if (password.length < 12 || password.length > 128 || password !== confirmation) {
    return {
      kind: "error",
      message: password !== confirmation
        ? "The passwords do not match."
        : "Use a password between 12 and 128 characters.",
    };
  }
  if (!getSupabaseEnvironmentStatus()) {
    return AUTH_NOT_CONFIGURED;
  }

  try {
    const supabase = await createSupabaseServerClient();
    const { data: claims, error: claimsError } = await supabase.auth.getClaims();
    if (claimsError || typeof claims?.claims?.sub !== "string") {
      return { kind: "error", message: "This reset link is invalid or expired. Request a new link to continue." };
    }
    const { error } = await supabase.auth.updateUser({ password });
    if (error) {
      return { kind: "error", message: "We couldn't update your password. Request a new reset link and try again." };
    }
  } catch {
    return authUnavailable();
  }

  return { kind: "success", message: "Your password has been updated. You can now sign in with it." };
}

export async function updateProfileAction(
  _previousState: AuthActionState,
  formData: FormData,
): Promise<AuthActionState> {
  const fullName = formText(formData, "full_name").trim();
  const avatarValue = formText(formData, "avatar_url").trim();
  if (fullName.length < 2 || fullName.length > 160 || avatarValue.length > 2048) {
    return INVALID_FORM;
  }

  let avatarUrl: string | null = null;
  if (avatarValue) {
    try {
      const parsed = new URL(avatarValue);
      if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
        return { kind: "error", message: "Avatar URLs must use HTTPS." };
      }
      avatarUrl = parsed.toString();
    } catch {
      return { kind: "error", message: "Enter a valid HTTPS avatar URL or leave it blank." };
    }
  }
  if (!getSupabaseEnvironmentStatus()) {
    return AUTH_NOT_CONFIGURED;
  }

  try {
    const supabase = await createSupabaseServerClient();
    const { data: claims, error: claimsError } = await supabase.auth.getClaims();
    const userId = claims?.claims?.sub;
    if (claimsError || typeof userId !== "string") {
      return { kind: "error", message: "Your session has expired. Sign in again to update your profile." };
    }

    const { error } = await supabase
      .from("profiles")
      .update({ full_name: fullName, avatar_url: avatarUrl })
      .eq("id", userId);
    if (error) {
      return { kind: "error", message: "We couldn't save your profile. Please try again." };
    }
  } catch {
    return authUnavailable();
  }

  return { kind: "success", message: "Profile updated." };
}

export async function signOutAction(): Promise<void> {
  if (getSupabaseEnvironmentStatus()) {
    try {
      const supabase = await createSupabaseServerClient();
      await supabase.auth.signOut();
    } catch {
      // The protected pages still require a valid session after this redirect.
    }
  }
  redirect("/auth/login");
}
