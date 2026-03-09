import { statusConfig } from "@/lib/utils";
import { cn } from "@/lib/utils";

export function StatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] || statusConfig.new;
  const label = status.replace("_", " ");

  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded-md text-[12px] font-semibold capitalize",
        config.bg,
        config.color
      )}
    >
      {label}
    </span>
  );
}
