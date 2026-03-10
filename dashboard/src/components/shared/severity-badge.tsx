import { severityConfig } from "@/lib/utils";
import { cn } from "@/lib/utils";

export function SeverityBadge({ severity }: { severity: string }) {
  const config = severityConfig[severity] || severityConfig.info;

  return (
    <span
      className={cn(
        "inline-flex items-center h-[22px] px-2 rounded text-[11px] font-bold uppercase tracking-wide",
        config.bg,
        config.color
      )}
    >
      {config.label}
    </span>
  );
}
