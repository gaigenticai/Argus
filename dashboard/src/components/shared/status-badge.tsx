import { statusConfig } from "@/lib/utils";

export function StatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] || statusConfig.new;
  const label = status.replace("_", " ");

  const style: Record<string, { bg: string; color: string; border: string }> = {
    new:         { bg: "rgba(255,79,0,0.08)", color: "var(--color-accent)", border: "rgba(255,79,0,0.2)" },
    needs_review: { bg: "rgba(255,171,0,0.10)", color: "#B76E00", border: "rgba(255,171,0,0.3)" },
    open:        { bg: "rgba(59,130,246,0.07)", color: "#006c9c", border: "rgba(59,130,246,0.2)" },
    in_progress: { bg: "rgba(245,158,11,0.08)", color: "#b76e00", border: "rgba(245,158,11,0.25)" },
    resolved:    { bg: "rgba(34,197,94,0.07)", color: "#118d57", border: "rgba(34,197,94,0.2)" },
    closed:      { bg: "var(--color-surface-muted)", color: "var(--color-muted)", border: "var(--color-border)" },
    false_positive: { bg: "var(--color-surface-muted)", color: "var(--color-muted)", border: "var(--color-border)" },
  };

  const s = style[status] || style.closed;

  return (
    <span
      className="inline-flex items-center h-[19px] px-1.5 text-[10px] font-semibold capitalize"
      style={{
        background: s.bg,
        color: s.color,
        border: `1px solid ${s.border}`,
        borderRadius: "4px",
      }}
    >
      {label}
    </span>
  );
}
