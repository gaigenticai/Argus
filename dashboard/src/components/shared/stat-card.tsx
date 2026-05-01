import { type LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  /** Accent color for the icon. Defaults to Zapier orange. */
  color?: string;
  /** Unused — kept for call-site compat. Pass anything; the card is always cream+border. */
  bgColor?: string;
  /** Unused — kept for call-site compat. */
  tone?: "cream" | "saturated" | "saturated-dark";
}

/**
 * Zapier-style stat tile.
 * Border-forward: cream canvas with sand border, no shadow elevation.
 * The icon gets an optional accent color; the value uses Zapier ink.
 */
export function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  color = "var(--color-accent)",
}: StatCardProps) {
  return (
    <div
      className="p-5"
      style={{
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: "5px",
      }}
    >
      <div className="flex items-center justify-between mb-3">
        <span
          className="text-[11px] font-semibold uppercase tracking-[0.8px]"
          style={{ color: "var(--color-muted)" }}
        >
          {title}
        </span>
        <Icon
          className="w-4 h-4"
          style={{ color }}
          strokeWidth={1.75}
        />
      </div>
      <p
        className="text-[36px] font-medium leading-none tracking-[-0.02em]"
        style={{ color: "var(--color-ink)" }}
      >
        {value}
      </p>
      {subtitle && (
        <p
          className="text-[12px] mt-2 font-medium"
          style={{ color: "var(--color-muted)" }}
        >
          {subtitle}
        </p>
      )}
    </div>
  );
}
