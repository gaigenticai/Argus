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
      <div className="flex items-center justify-center h-[240px] text-sm text-grey-500">
        No alerts yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={chartData} layout="vertical" margin={{ left: 20 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#F4F6F8" horizontal={false} />
        <XAxis type="number" tick={{ fontSize: 12, fill: "#919EAB" }} />
        <YAxis
          type="category"
          dataKey="name"
          tick={{ fontSize: 11, fill: "#637381" }}
          width={120}
        />
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
          cursor={{ fill: "rgba(145,158,171,0.08)" }}
        />
        <Bar dataKey="count" fill="#00A76F" radius={[0, 4, 4, 0]} barSize={16} />
      </BarChart>
    </ResponsiveContainer>
  );
}
