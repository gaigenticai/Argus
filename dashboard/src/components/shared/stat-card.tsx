import { type LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  color: string;
  bgColor: string;
}

export function StatCard({ title, value, subtitle, icon: Icon, color, bgColor }: StatCardProps) {
  return (
    <div className="bg-white rounded-xl border border-grey-200 p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-[13px] font-semibold text-grey-600">{title}</span>
        <Icon className="w-5 h-5" style={{ color }} />
      </div>
      <p className="text-[28px] font-extrabold text-grey-900 leading-none" style={{ color }}>{value}</p>
      {subtitle && (
        <p className="text-[12px] text-grey-500 mt-1.5">{subtitle}</p>
      )}
    </div>
  );
}
