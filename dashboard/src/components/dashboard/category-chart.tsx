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
      <div className="flex items-center justify-center h-[240px] text-[14px] text-[#919EAB]">
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
            borderRadius: "8px",
            color: "#fff",
            fontSize: "13px",
          }}
        />
        <Bar dataKey="count" fill="#00A76F" radius={[0, 4, 4, 0]} barSize={16} />
      </BarChart>
    </ResponsiveContainer>
  );
}
