/** Illustrative UI values only. Never use these as scan results or security evidence. */
export const DEMO_RISK_DISTRIBUTION = [
  { label: "Critical", value: 4, color: "bg-negative" },
  { label: "High", value: 13, color: "bg-[#f39b73]" },
  { label: "Medium", value: 29, color: "bg-warning" },
  { label: "Low / info", value: 54, color: "bg-accent" },
] as const;
