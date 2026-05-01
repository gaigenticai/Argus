"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { categoryLabels } from "@/lib/utils";

interface CategoryChartProps {
  data: Record<string, number>;
}

export function CategoryChart({ data }: CategoryChartProps) {
  const chartData = Object.entries(data)
    .map(([key, value]) => ({
      name: categoryLabels[key] || key,
      count: value,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  if (chartData.length === 0) {
    return (
      <div className="flex items-center justify-center h-[240px] text-[13px]" style={{ color: "var(--color-muted)" }}>
        No alerts yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={chartData} layout="vertical" margin={{ left: 20 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-surface-muted)" horizontal={false} />
        <XAxis type="number" tick={{ fontSize: 12, fill: "var(--color-muted)" }} />
        <YAxis
          type="category"
          dataKey="name"
          tick={{ fontSize: 11, fill: "var(--color-body)" }}
          width={120}
        />
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
          cursor={{ fill: "rgba(197,192,177,0.15)" }}
        />
        <Bar dataKey="count" fill="var(--color-accent)" radius={[0, 4, 4, 0]} barSize={16} />
      </BarChart>
    </ResponsiveContainer>
  );
}
