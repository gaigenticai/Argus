/**
 * Shared visual primitives — Zapier design language.
 * Border-forward, warm cream canvas, sand borders, tight radii (4–8px).
 * Orange (#ff4f00) is reserved for CTAs and active state indicators only.
 */

"use client";

import { cn } from "@/lib/utils";
import { Clock } from "lucide-react";
import type { ReactNode } from "react";

// ---------------------------------------------------------------------
//  Severity (canonical 5-tier)
// ---------------------------------------------------------------------

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEV: Record<
  Severity,
  { stripe: string; label: string; rank: number; badgeBg: string; badgeColor: string; badgeBorder: string }
> = {
  critical: {
    stripe: "bg-error",
    label: "CRIT",
    rank: 4,
    badgeBg: "rgba(239,68,68,0.08)",
    badgeColor: "var(--color-error-dark)",
    badgeBorder: "rgba(239,68,68,0.3)",
  },
  high: {
    stripe: "bg-error-light",
    label: "HIGH",
    rank: 3,
    badgeBg: "rgba(239,68,68,0.05)",
    badgeColor: "var(--color-error-dark)",
    badgeBorder: "rgba(239,68,68,0.2)",
  },
  medium: {
    stripe: "bg-warning",
    label: "MED",
    rank: 2,
    badgeBg: "rgba(245,158,11,0.08)",
    badgeColor: "var(--color-warning-dark)",
    badgeBorder: "rgba(245,158,11,0.25)",
  },
  low: {
    stripe: "bg-info",
    label: "LOW",
    rank: 1,
    badgeBg: "rgba(59,130,246,0.07)",
    badgeColor: "var(--color-info-dark)",
    badgeBorder: "rgba(59,130,246,0.2)",
  },
  info: {
    stripe: "bg-grey-300",
    label: "INFO",
    rank: 0,
    badgeBg: "var(--color-surface-muted)",
    badgeColor: "var(--color-body)",
    badgeBorder: "var(--color-border)",
  },
};

export function SevPill({
  severity,
  size = "md",
}: {
  severity: Severity;
  size?: "sm" | "md";
}) {
  const s = SEV[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center font-bold tracking-[0.05em] uppercase",
        size === "sm" ? "h-[17px] px-1.5 text-[9px]" : "h-[19px] px-1.5 text-[10px]",
      )}
      style={{
        background: s.badgeBg,
        color: s.badgeColor,
        border: `1px solid ${s.badgeBorder}`,
        borderRadius: "4px",
      }}
    >
      {s.label}
    </span>
  );
}

export function SevStripe({ severity }: { severity: Severity }) {
  return <div className={cn("w-[3px] h-full self-stretch", SEV[severity].stripe)} />;
}

// ---------------------------------------------------------------------
//  Generic state pill
// ---------------------------------------------------------------------

export type StateTone =
  | "neutral"
  | "info"
  | "secondary"
  | "warning"
  | "warning-strong"
  | "primary"
  | "error"
  | "error-strong"
  | "success"
  | "muted";

const STATE_PALETTE: Record<StateTone, { bg: string; color: string; border: string }> = {
  neutral:         { bg: "var(--color-surface-muted)", color: "var(--color-body)", border: "var(--color-border)" },
  muted:           { bg: "var(--color-surface-muted)", color: "var(--color-muted)", border: "var(--color-border)" },
  info:            { bg: "rgba(59,130,246,0.07)", color: "var(--color-info-dark)", border: "rgba(59,130,246,0.2)" },
  secondary:       { bg: "var(--color-surface-muted)", color: "var(--color-body)", border: "var(--color-border)" },
  warning:         { bg: "rgba(245,158,11,0.08)", color: "var(--color-warning-dark)", border: "rgba(245,158,11,0.25)" },
  "warning-strong":{ bg: "rgba(245,158,11,0.12)", color: "var(--color-warning-darker)", border: "rgba(245,158,11,0.3)" },
  primary:         { bg: "rgba(255,79,0,0.08)", color: "var(--color-accent)", border: "rgba(255,79,0,0.2)" },
  error:           { bg: "rgba(239,68,68,0.08)", color: "var(--color-error-dark)", border: "rgba(239,68,68,0.25)" },
  "error-strong":  { bg: "rgba(239,68,68,0.12)", color: "var(--color-error-darker)", border: "rgba(239,68,68,0.3)" },
  success:         { bg: "rgba(34,197,94,0.07)", color: "var(--color-success-dark)", border: "rgba(34,197,94,0.2)" },
};

export function StatePill({ label, tone }: { label: string; tone: StateTone }) {
  const p = STATE_PALETTE[tone];
  return (
    <span
      className="inline-flex items-center h-[19px] px-1.5 text-[10px] font-bold tracking-[0.05em] whitespace-nowrap uppercase"
      style={{
        background: p.bg,
        color: p.color,
        border: `1px solid ${p.border}`,
        borderRadius: "4px",
      }}
    >
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------
//  Page header
// ---------------------------------------------------------------------

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: { icon: React.ElementType; label: string };
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  const Icon = eyebrow.icon;
  return (
    <div className="flex items-start justify-between gap-6 flex-wrap">
      <div>
        <div
          className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.8px] mb-1.5"
          style={{ color: "var(--color-muted)" }}
        >
          <Icon className="w-3 h-3" />
          {eyebrow.label}
        </div>
        <h1
          className="text-[24px] leading-[1.2] font-semibold tracking-[-0.02em]"
          style={{ color: "var(--color-ink)" }}
        >
          {title}
        </h1>
        {description && (
          <p className="text-[13px] mt-1 max-w-[640px]" style={{ color: "var(--color-body)" }}>
            {description}
          </p>
        )}
      </div>
      {actions && (
        <div className="flex items-center gap-2 flex-wrap">{actions}</div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------
//  Stat strip (border-only, no card background)
// ---------------------------------------------------------------------

export function StatStrip({
  cells,
}: {
  cells: Array<{
    label: string;
    value: number | string;
    tone?: "neutral" | "error";
    accent?: string;
    highlightLabel?: boolean;
  }>;
}) {
  return (
    <div
      className="overflow-hidden"
      style={{
        border: "1px solid var(--color-border)",
        borderRadius: "5px",
        background: "var(--color-canvas)",
      }}
    >
      <div
        className="grid"
        style={{
          gridTemplateColumns: `repeat(${cells.length}, minmax(0, 1fr))`,
        }}
      >
        {cells.map((c, i) => (
          <StatCell key={`${c.label}-${i}`} {...c} isLast={i === cells.length - 1} />
        ))}
      </div>
    </div>
  );
}

function StatCell({
  label,
  value,
  tone = "neutral",
  accent,
  highlightLabel,
  isLast,
}: {
  label: string;
  value: number | string;
  tone?: "neutral" | "error";
  accent?: string;
  highlightLabel?: boolean;
  isLast?: boolean;
}) {
  return (
    <div
      className="px-4 py-4 relative"
      style={!isLast ? { borderRight: "1px solid var(--color-border)" } : {}}
    >
      {accent && (
        <span
          className={cn("absolute left-0 top-3 bottom-3 w-[2px] rounded-r", accent)}
        />
      )}
      <div
        className="text-[10px] font-bold uppercase tracking-[0.1em]"
        style={{ color: highlightLabel ? "var(--color-error-dark)" : "var(--color-muted)" }}
      >
        {label}
      </div>
      <div
        className="mt-1.5 font-mono tabular-nums text-[26px] leading-none font-semibold tracking-[-0.01em]"
        style={{ color: tone === "error" ? "var(--color-error)" : "var(--color-ink)" }}
      >
        {value}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------
//  Table primitives
// ---------------------------------------------------------------------

export function Th({
  children,
  align = "left",
  className,
}: {
  children: ReactNode;
  align?: "left" | "right" | "center";
  className?: string;
}) {
  return (
    <th
      className={cn(
        "h-9 px-3 text-[10px] font-semibold uppercase tracking-[0.07em]",
        align === "right" ? "text-right" : align === "center" ? "text-center" : "text-left",
        className,
      )}
      style={{ color: "var(--color-muted)" }}
    >
      {children}
    </th>
  );
}

export function MonoCell({ text, className }: { text: string; className?: string }) {
  return (
    <span
      className={cn("font-mono text-[11.5px] tabular-nums tracking-wide", className)}
      style={{ color: "var(--color-muted)" }}
    >
      {text}
    </span>
  );
}

export function ShortId({ uuid }: { uuid: string }) {
  return <MonoCell text={uuid.slice(-6).toUpperCase()} />;
}

// ---------------------------------------------------------------------
//  Section wrapper
// ---------------------------------------------------------------------

export function Section({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn("overflow-hidden", className)}
      style={{
        border: "1px solid var(--color-border)",
        borderRadius: "5px",
        background: "var(--color-canvas)",
      }}
    >
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------
//  Empty state
// ---------------------------------------------------------------------

export function Empty({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: React.ElementType;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-14 px-6 text-center">
      <div
        className="w-10 h-10 flex items-center justify-center mb-4"
        style={{
          background: "var(--color-surface-muted)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
        }}
      >
        <Icon className="w-5 h-5" style={{ color: "var(--color-muted)" }} />
      </div>
      <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
        {title}
      </h3>
      <p className="text-[13px] mt-1 max-w-[440px]" style={{ color: "var(--color-muted)" }}>
        {description}
      </p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------
//  Skeleton rows
// ---------------------------------------------------------------------

export function SkeletonRows({ rows, columns }: { rows: number; columns: number }) {
  return (
    <div style={{ borderTop: "1px solid var(--color-border)" }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="h-12 px-4 flex items-center gap-4 animate-pulse"
          style={{
            animationDelay: `${i * 60}ms`,
            borderBottom: "1px solid var(--color-border)",
          }}
        >
          {Array.from({ length: columns }).map((__, c) => (
            <div
              key={c}
              className={cn(
                "h-2.5 rounded",
                c === 0 ? "w-12" : c === 1 ? "w-16" : c === columns - 1 ? "w-16 ml-auto" : "flex-1 max-w-[220px]",
              )}
              style={{ background: "var(--color-surface-muted)" }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------
//  Pagination footer
// ---------------------------------------------------------------------

import { ChevronLeft, ChevronRight } from "lucide-react";

export function PaginationFooter({
  total,
  limit,
  offset,
  shown,
  onPrev,
  onNext,
}: {
  total: number;
  limit: number;
  offset: number;
  shown: number;
  onPrev: () => void;
  onNext: () => void;
}) {
  const totalPages = Math.max(1, Math.ceil(total / Math.max(limit, 1)));
  const currentPage = Math.floor(offset / Math.max(limit, 1)) + 1;
  return (
    <div
      className="flex items-center justify-between px-4 py-3"
      style={{
        borderTop: "1px solid var(--color-border)",
        background: "var(--color-surface)",
      }}
    >
      <div className="text-[12px] font-mono tabular-nums" style={{ color: "var(--color-body)" }}>
        {shown === 0 ? "0 of 0" : `${offset + 1}–${offset + shown} of ${total}`}
      </div>
      <div className="flex items-center gap-1">
        <button
          onClick={onPrev}
          disabled={offset === 0}
          className="h-7 w-7 flex items-center justify-center transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          style={{
            border: "1px solid var(--color-border)",
            borderRadius: "4px",
            color: "var(--color-body)",
          }}
          onMouseEnter={(e) => {
            if (!e.currentTarget.disabled) (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "";
          }}
        >
          <ChevronLeft className="w-3.5 h-3.5" />
        </button>
        <span
          className="text-[12px] font-mono tabular-nums px-2"
          style={{ color: "var(--color-body)" }}
        >
          {currentPage} / {totalPages}
        </span>
        <button
          onClick={onNext}
          disabled={currentPage >= totalPages}
          className="h-7 w-7 flex items-center justify-center transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          style={{
            border: "1px solid var(--color-border)",
            borderRadius: "4px",
            color: "var(--color-body)",
          }}
          onMouseEnter={(e) => {
            if (!e.currentTarget.disabled) (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "";
          }}
        >
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------
//  Search + filter row
// ---------------------------------------------------------------------

import { ChevronDown, Search as SearchIcon } from "lucide-react";

export function SearchInput({
  value,
  onChange,
  placeholder = "Search…",
  shortcut = "/",
  refEl,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  shortcut?: string;
  refEl?: React.RefObject<HTMLInputElement | null>;
  className?: string;
}) {
  return (
    <div className={cn("relative flex-1 min-w-[220px] max-w-[400px]", className)}>
      <SearchIcon
        className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
        style={{ color: "var(--color-muted)" }}
      />
      <input
        ref={refEl}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full h-9 pl-8 pr-8 text-[13px] outline-none transition-colors placeholder:opacity-60"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
          color: "var(--color-ink)",
        }}
        onFocus={(e) => {
          (e.target as HTMLInputElement).style.borderColor = "var(--color-accent)";
        }}
        onBlur={(e) => {
          (e.target as HTMLInputElement).style.borderColor = "var(--color-border)";
        }}
      />
      {shortcut && (
        <kbd
          className="absolute right-2 top-1/2 -translate-y-1/2 inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 text-[10px] font-mono font-semibold"
          style={{
            background: "var(--color-surface-muted)",
            border: "1px solid var(--color-border)",
            borderRadius: "3px",
            color: "var(--color-muted)",
          }}
        >
          {shortcut}
        </kbd>
      )}
    </div>
  );
}

export function Select<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
}: {
  value: T;
  options: Array<{ value: T; label: string }>;
  onChange: (v: T) => void;
  ariaLabel: string;
}) {
  return (
    <div className="relative">
      <select
        aria-label={ariaLabel}
        value={value}
        onChange={(e) => onChange(e.target.value as T)}
        className="h-9 pl-3 pr-8 text-[13px] font-semibold outline-none appearance-none transition-colors"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
          color: "var(--color-ink)",
        }}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <ChevronDown
        className="w-3.5 h-3.5 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none"
        style={{ color: "var(--color-muted)" }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------
//  Org switcher
// ---------------------------------------------------------------------

export type OrgState =
  | { status: "loading" }
  | { status: "ready"; orgs: import("@/lib/api").Org[]; orgId: string }
  | { status: "empty" };

export function OrgSwitcher({
  orgs,
  orgId,
  onChange,
}: {
  orgs: import("@/lib/api").Org[];
  orgId: string;
  onChange: (id: string) => void;
}) {
  if (orgs.length <= 1) return null;
  return (
    <div className="relative">
      <select
        value={orgId}
        onChange={(e) => onChange(e.target.value)}
        aria-label="Organization"
        className="h-9 pl-3 pr-9 text-[13px] font-semibold outline-none appearance-none max-w-[240px] transition-colors"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
          color: "var(--color-ink)",
        }}
      >
        {orgs.map((o) => (
          <option key={o.id} value={o.id}>{o.name}</option>
        ))}
      </select>
      <ChevronDown
        className="w-3.5 h-3.5 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none"
        style={{ color: "var(--color-muted)" }}
      />
    </div>
  );
}

import { RefreshCw } from "lucide-react";

export function RefreshButton({ onClick, refreshing }: { onClick: () => void; refreshing: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={refreshing}
      className="flex items-center gap-2 h-9 px-3 text-[13px] font-semibold transition-colors disabled:opacity-50"
      style={{
        border: "1px solid var(--color-border)",
        borderRadius: "5px",
        color: "var(--color-body)",
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLElement).style.background = "";
      }}
    >
      <RefreshCw className={cn("w-3.5 h-3.5", refreshing && "animate-spin")} />
      Refresh
    </button>
  );
}

// ---------------------------------------------------------------------
//  Modal shell + footer
// ---------------------------------------------------------------------

import { X } from "lucide-react";

export function ModalShell({
  title,
  onClose,
  children,
  width = 520,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  width?: number;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-6"
      style={{ background: "rgba(32, 21, 21, 0.45)" }}
      onClick={onClose}
    >
      <div
        className="w-full overflow-hidden"
        style={{
          maxWidth: width,
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "8px",
          boxShadow: "var(--shadow-z24)",
        }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
      >
        <div
          className="px-5 pt-5 pb-4 flex items-center justify-between"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <h2
            className="text-[15px] font-semibold tracking-tight"
            style={{ color: "var(--color-ink)" }}
          >
            {title}
          </h2>
          <button
            onClick={onClose}
            className="p-1.5 transition-colors"
            style={{ borderRadius: "4px", color: "var(--color-muted)" }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
              (e.currentTarget as HTMLElement).style.color = "var(--color-ink)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLElement).style.background = "";
              (e.currentTarget as HTMLElement).style.color = "var(--color-muted)";
            }}
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function ModalFooter({
  onCancel,
  onSubmit,
  submitLabel,
  submitTone,
  disabled,
}: {
  onCancel: () => void;
  onSubmit: () => void;
  submitLabel: string;
  submitTone?: "error" | "primary";
  disabled?: boolean;
}) {
  return (
    <div
      className="px-5 py-4 flex items-center justify-end gap-2"
      style={{
        borderTop: "1px solid var(--color-border)",
        background: "var(--color-surface)",
      }}
    >
      <button
        onClick={onCancel}
        className="h-8 px-3 text-[13px] font-semibold transition-colors"
        style={{
          border: "1px solid var(--color-border)",
          borderRadius: "4px",
          color: "var(--color-body)",
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLElement).style.background = "";
        }}
      >
        Cancel
      </button>
      <button
        onClick={onSubmit}
        disabled={disabled}
        className="h-8 px-4 text-[13px] font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        style={{
          background: submitTone === "error" ? "var(--color-error)" : "var(--color-accent)",
          color: "#fffefb",
          borderRadius: "4px",
          border: `1px solid ${submitTone === "error" ? "var(--color-error)" : "var(--color-accent)"}`,
        }}
        onMouseEnter={(e) => {
          if (!disabled) (e.currentTarget as HTMLElement).style.opacity = "0.88";
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLElement).style.opacity = "";
        }}
      >
        {submitLabel}
      </button>
    </div>
  );
}

export function Field({
  label,
  hint,
  required,
  children,
}: {
  label: string;
  hint?: string;
  required?: boolean;
  children: ReactNode;
}) {
  return (
    <div>
      <div className="flex items-baseline gap-1.5 mb-1.5">
        <label
          className="text-[11px] font-semibold uppercase tracking-[0.08em]"
          style={{ color: "var(--color-body)" }}
        >
          {label}
        </label>
        {required && (
          <span className="text-[10px] font-bold" style={{ color: "var(--color-accent)" }}>
            *
          </span>
        )}
      </div>
      {children}
      {hint && (
        <p className="text-[11.5px] mt-1.5" style={{ color: "var(--color-muted)" }}>
          {hint}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------
//  SLA helpers
// ---------------------------------------------------------------------

export function durationLabel(ms: number): string {
  const abs = Math.abs(ms);
  const minutes = Math.floor(abs / 60000);
  if (minutes < 60) return `${minutes}M`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}H`;
  const days = Math.floor(hours / 24);
  return `${days}D`;
}

export { Clock };
