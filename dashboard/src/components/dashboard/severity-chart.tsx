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
  info: "#919EAB",
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
      <div className="flex items-center justify-center h-[240px] text-sm text-grey-500">
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
            <Cell key={entry.key} fill={COLORS[entry.key] || "#919EAB"} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: "#1C252E",
            border: "none",
            borderRadius: 8,
            color: "#FFFFFF",
            fontSize: 13,
            padding: "8px 12px",
          }}
          itemStyle={{ color: "#FFFFFF" }}
        />
        <Legend
          iconType="circle"
          iconSize={8}
          wrapperStyle={{ fontSize: 12, color: "#637381" }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
