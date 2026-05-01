"use client";

import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";

const COLORS: Record<string, string> = {
  critical: "#FF5630",
  high: "#FFAB00",
  medium: "#FFD666",
  low: "#00BBD9",
  info: "#939084",
};

interface SeverityChartProps {
  data: Record<string, number>;
}

export function SeverityChart({ data }: SeverityChartProps) {
  const chartData = Object.entries(data).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    key: name,
  }));

  if (chartData.length === 0) {
    return (
      <div className="flex items-center justify-center h-[240px] text-[13px]" style={{ color: "var(--color-muted)" }}>
        No alerts yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={90}
          paddingAngle={3}
          dataKey="value"
          stroke="none"
        >
          {chartData.map((entry) => (
            <Cell key={entry.key} fill={COLORS[entry.key] || "#939084"} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: "var(--color-surface-dark)",
            border: "1px solid var(--color-border-strong)",
            borderRadius: 5,
            color: "var(--color-on-dark)",
            fontSize: 13,
            padding: "8px 12px",
          }}
          itemStyle={{ color: "var(--color-on-dark)" }}
        />
        <Legend
          iconType="circle"
          iconSize={8}
          wrapperStyle={{ fontSize: 12, color: "var(--color-muted)" }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
