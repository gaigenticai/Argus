import { severityConfig } from "@/lib/utils";

export function SeverityBadge({ severity }: { severity: string }) {
  const config = severityConfig[severity] || severityConfig.info;

  const style: Record<string, { bg: string; color: string; border: string }> = {
    critical: { bg: "rgba(239,68,68,0.08)", color: "#b71d18", border: "rgba(239,68,68,0.3)" },
    high:     { bg: "rgba(239,68,68,0.05)", color: "#b71d18", border: "rgba(239,68,68,0.2)" },
    medium:   { bg: "rgba(245,158,11,0.08)", color: "#b76e00", border: "rgba(245,158,11,0.25)" },
    low:      { bg: "rgba(59,130,246,0.07)", color: "#006c9c", border: "rgba(59,130,246,0.2)" },
    info:     { bg: "var(--color-surface-muted)", color: "var(--color-body)", border: "var(--color-border)" },
  };

  const s = style[severity] || style.info;

  return (
    <span
      className="inline-flex items-center h-[19px] px-1.5 text-[10px] font-bold uppercase tracking-[0.05em]"
      style={{
        background: s.bg,
        color: s.color,
        border: `1px solid ${s.border}`,
        borderRadius: "4px",
      }}
    >
      {config.label}
    </span>
  );
}
