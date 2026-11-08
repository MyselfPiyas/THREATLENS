const LOCAL_ORIGIN = "https://threatlens.invalid";

export function getSafeRedirectPath(value: unknown, fallback = "/dashboard"): string {
  if (
    typeof value !== "string" ||
    value.length > 2048 ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("\\") ||
    value.includes("\0")
  ) {
    return fallback;
  }

  try {
    const parsed = new URL(value, LOCAL_ORIGIN);
    if (parsed.origin !== LOCAL_ORIGIN) {
      return fallback;
    }
    return parsed.pathname + parsed.search + parsed.hash;
  } catch {
    return fallback;
  }
}
