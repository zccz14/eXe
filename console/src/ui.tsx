import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...values: ClassValue[]): string {
  return twMerge(clsx(values));
}

export function Button({
  variant = "default",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "default" | "outline" | "ghost" | "destructive" }) {
  const styles = {
    default: "bg-foreground text-background hover:opacity-90",
    outline: "border border-border bg-transparent hover:bg-accent",
    ghost: "bg-transparent hover:bg-accent",
    destructive: "bg-destructive text-white hover:opacity-90",
  }[variant];
  return (
    <button
      {...props}
      className={cn(
        "inline-flex h-9 items-center justify-center gap-2 rounded-md px-3 text-sm font-medium transition disabled:pointer-events-none disabled:opacity-50",
        styles,
        className,
      )}
    />
  );
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cn(
        "h-9 w-full rounded-md border border-border bg-transparent px-3 text-sm outline-none placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring",
        className,
      )}
    />
  );
}

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("rounded-xl border border-border bg-card p-4 text-card-foreground", className)}>{children}</div>;
}

export function Badge({ tone = "muted", children }: { tone?: "muted" | "ok" | "warn" | "bad"; children: ReactNode }) {
  const styles = {
    muted: "border-border text-muted-foreground",
    ok: "border-emerald-500/40 text-emerald-600 dark:text-emerald-400",
    warn: "border-amber-500/40 text-amber-600 dark:text-amber-400",
    bad: "border-destructive/40 text-destructive",
  }[tone];
  return <span className={cn("inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium", styles)}>{children}</span>;
}

export function Stat({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="space-y-1">
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className={cn("text-sm", mono && "font-mono text-xs break-all")}>{value}</div>
    </div>
  );
}
