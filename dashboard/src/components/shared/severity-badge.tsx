import { severityConfig } from "@/lib/utils";
import { cn } from "@/lib/utils";

export function SeverityBadge({ severity }: { severity: string }) {
  const config = severityConfig[severity] || severityConfig.info;

  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded-md text-[12px] font-bold uppercase",
        config.bg,
        config.color
      )}
    >
      {config.label}
    </span>
  );
}
