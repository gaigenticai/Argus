import { cn } from "@/lib/utils";
import { type LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  color: string; // hex
  bgColor: string; // hex
}

export function StatCard({ title, value, subtitle, icon: Icon, color, bgColor }: StatCardProps) {
  return (
    <div className="bg-white rounded-2xl p-6 shadow-[0_0_2px_0_rgba(145,158,171,0.2),0_12px_24px_-4px_rgba(145,158,171,0.12)]">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-[14px] font-semibold text-[#637381]">{title}</p>
          <p className="text-[32px] font-extrabold mt-1" style={{ color }}>{value}</p>
          {subtitle && (
            <p className="text-[12px] text-[#919EAB] mt-1">{subtitle}</p>
          )}
        </div>
        <div
          className="w-12 h-12 rounded-xl flex items-center justify-center"
          style={{ backgroundColor: bgColor }}
        >
          <Icon className="w-6 h-6" style={{ color }} />
        </div>
      </div>
    </div>
  );
}
