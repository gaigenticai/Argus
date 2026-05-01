"use client";

import { useCallback, useEffect, useState } from "react";
import { Activity, Ban, RotateCcw } from "lucide-react";
import {
  api,
  type DiscoveryJobRecord,
  type DiscoveryJobStatusName,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Section,
  Select,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { useExposuresContext } from "./use-exposures-context";

const STATUS_TONE: Record<DiscoveryJobStatusName, StateTone> = {
  queued: "info",
  running: "warning",
  succeeded: "success",
  failed: "error-strong",
  cancelled: "muted",
};

export function JobsTab() {
  const { orgId, bumpRefresh } = useExposuresContext();
  const { toast } = useToast();
  const [rows, setRows] = useState<DiscoveryJobRecord[]>([]);
  const [statusFilter, setStatusFilter] = useState("all");
  const [kindFilter, setKindFilter] = useState("all");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const data = await api.listDiscoveryJobs({
        organization_id: orgId,
        status: statusFilter === "all" ? undefined : statusFilter,
        kind: kindFilter === "all" ? undefined : kindFilter,
        limit: 100,
      });
      setRows(data);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load discovery jobs",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, statusFilter, kindFilter, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const cancel = async (id: string) => {
    if (!confirm("Cancel this queued discovery job?")) return;
    try {
      await api.cancelDiscoveryJob(id);
      toast("success", "Job cancelled");
      await load();
      bumpRefresh();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to cancel job",
      );
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="Status"
          value={statusFilter}
          options={[
            { value: "all", label: "Any status" },
            { value: "queued", label: "Queued" },
            { value: "running", label: "Running" },
            { value: "succeeded", label: "Succeeded" },
            { value: "failed", label: "Failed" },
            { value: "cancelled", label: "Cancelled" },
          ]}
          onChange={(v) => setStatusFilter(v)}
        />
        <Select
          ariaLabel="Kind"
          value={kindFilter}
          options={[
            { value: "all", label: "Any kind" },
            { value: "subdomain_enum", label: "Subdomain enumeration" },
            { value: "port_scan", label: "Port scan" },
            { value: "httpx_probe", label: "HTTPX probe" },
            { value: "ct_log_backfill", label: "CT log backfill" },
            { value: "whois_refresh", label: "WHOIS refresh" },
            { value: "dns_refresh", label: "DNS refresh" },
          ]}
          onChange={(v) => setKindFilter(v)}
        />
      </div>

      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={5} />
        ) : rows.length === 0 ? (
          <Empty
            icon={Activity}
            title="No discovery jobs match"
            description="EASM jobs are queued by the onboarding wizard, the worker tick, or the manual scan endpoint. Each row tracks one ENUM-style task — subdomain enum, port scan, HTTPX probe, CT-log backfill."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[140px]">
                    Kind
                  </Th>
                  <Th align="left">Target</Th>
                  <Th align="left" className="w-[110px]">
                    Status
                  </Th>
                  <Th align="left" className="w-[110px]">
                    Started
                  </Th>
                  <Th align="left" className="w-[110px]">
                    Finished
                  </Th>
                  <Th align="left">Result</Th>
                  <Th align="right" className="pr-4 w-[80px]">
                    &nbsp;
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((j) => (
                  <JobRow key={j.id} j={j} onCancel={() => cancel(j.id)} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}

function JobRow({ j, onCancel }: { j: DiscoveryJobRecord; onCancel: () => void }) {
  const [hovered, setHovered] = useState(false);
  const [cancelHov, setCancelHov] = useState(false);
  return (
    <tr
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: hovered ? "var(--color-surface)" : "transparent",
        transition: "background 0.15s",
      }}
    >
      <td className="pl-4">
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          height: "18px",
          padding: "0 6px",
          borderRadius: "4px",
          background: "var(--color-surface-muted)",
          fontSize: "10.5px",
          fontWeight: 700,
          color: "var(--color-body)",
          letterSpacing: "0.06em",
        }}>
          {j.kind.replace(/_/g, " ").toUpperCase()}
        </span>
      </td>
      <td style={{ padding: "0 12px", fontFamily: "monospace", fontSize: "12.5px", color: "var(--color-ink)", maxWidth: "280px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {j.target}
      </td>
      <td className="px-3">
        <StatePill
          label={j.status}
          tone={STATUS_TONE[j.status]}
        />
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {j.started_at ? timeAgo(j.started_at) : "—"}
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {j.finished_at ? timeAgo(j.finished_at) : "—"}
      </td>
      <td className="px-3" style={{ fontSize: "12px", color: "var(--color-body)" }}>
        {j.error_message ? (
          <span style={{ color: "#B71D18" }} className="line-clamp-1">
            {j.error_message}
          </span>
        ) : j.result_summary ? (
          <ResultSummary data={j.result_summary} />
        ) : (
          <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>pending</span>
        )}
      </td>
      <td className="pr-4">
        <div className="flex items-center justify-end">
          {j.status === "queued" || j.status === "running" ? (
            <button
              onClick={onCancel}
              onMouseEnter={() => setCancelHov(true)}
              onMouseLeave={() => setCancelHov(false)}
              style={{
                padding: "6px",
                borderRadius: "4px",
                border: "none",
                background: cancelHov ? "rgba(255,86,48,0.1)" : "none",
                color: cancelHov ? "#FF5630" : "var(--color-muted)",
                cursor: "pointer",
                transition: "background 0.15s, color 0.15s",
              }}
              aria-label="Cancel"
            >
              <Ban style={{ width: "14px", height: "14px" }} />
            </button>
          ) : (
            <RotateCcw style={{ width: "14px", height: "14px", color: "var(--color-border)" }} />
          )}
        </div>
      </td>
    </tr>
  );
}

function ResultSummary({ data }: { data: Record<string, unknown> }) {
  // Pick the most informative scalar fields for a one-line summary —
  // "items_found", "duration_ms", "errors" are common shapes.
  const entries = Object.entries(data).filter(
    ([, v]) =>
      typeof v === "number" || typeof v === "string" || typeof v === "boolean",
  );
  if (entries.length === 0) return <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>empty</span>;
  return (
    <span style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-body)" }} className="line-clamp-1">
      {entries
        .slice(0, 4)
        .map(([k, v]) => `${k}=${v}`)
        .join(" · ")}
    </span>
  );
}
