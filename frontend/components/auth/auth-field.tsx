import type { InputHTMLAttributes } from "react";

type AuthFieldProps = InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: string;
};

export function AuthField({ label, hint, id, className, ...inputProps }: AuthFieldProps) {
  const inputId = id ?? inputProps.name;
  return (
    <div className="space-y-2">
      {label ? (
        <label htmlFor={inputId} className="block text-xs font-medium text-foreground">
          {label}
        </label>
      ) : null}
      <input
        {...inputProps}
        id={inputId}
        className={"h-11 w-full rounded-lg border border-border bg-panel-raised px-3.5 text-sm text-foreground outline-none transition placeholder:text-muted-foreground/65 focus:border-accent/60 focus:ring-2 focus:ring-accent/10 disabled:opacity-50 " + (className ?? "")}
      />
      {hint ? <p className="text-[11px] leading-5 text-muted-foreground">{hint}</p> : null}
    </div>
  );
}
