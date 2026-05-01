"use client";

import { useCallback, useEffect, useState } from "react";
import { Check, Target, X } from "lucide-react";
import { api, type EasmFindingResponse } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Field,
  ModalFooter,
  ModalShell,
  PaginationFooter,
  Section,
  Select,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { useExposuresContext } from "./use-exposures-context";

const STATE_TONE: Record<string, StateTone> = {
  new: "info",
  promoted: "success",
  dismissed: "muted",
  ignored: "muted",
};

const PAGE_LIMIT = 50;

export function FindingsTab() {
  const { orgId, bumpRefresh } = useExposuresContext();
  const { toast } = useToast();
  const [rows, setRows] = useState<EasmFindingResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [stateFilter, setStateFilter] = useState("all");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [promoteTarget, setPromoteTarget] =
    useState<EasmFindingResponse | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const { data, page } = await api.easm.listFindings({
        organization_id: orgId,
        state: stateFilter === "all" ? undefined : stateFilter,
        limit: PAGE_LIMIT,
        offset,
      });
      setRows(data);
      setTotal(page.total ?? data.length);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load findings",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, stateFilter, offset, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const dismiss = async (f: EasmFindingResponse) => {
    if (!confirm(`Dismiss this ${f.asset_type} finding?`)) return;
    try {
      await api.easm.dismissFinding(f.id);
      toast("success", "Finding dismissed");
      await load();
      bumpRefresh();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to dismiss",
      );
    }
  };

  const promote = async (
    f: EasmFindingResponse,
  ): Promise<void> => {
    try {
      await api.easm.promoteFinding(f.id);
      toast("success", `Promoted ${f.value} into the asset registry`);
      setPromoteTarget(null);
      await load();
      bumpRefresh();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to promote",
      );
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="State"
          value={stateFilter}
          options={[
            { value: "all", label: "Any state" },
            { value: "new", label: "New" },
            { value: "promoted", label: "Promoted" },
            { value: "dismissed", label: "Dismissed" },
          ]}
          onChange={(v) => {
            setStateFilter(v);
            setOffset(0);
          }}
        />
        <p style={{ fontSize: "12px", color: "var(--color-muted)", marginLeft: "auto", fontFamily: "monospace" }}>
          {total} finding{total === 1 ? "" : "s"}
        </p>
      </div>

      <Section>
        {loading ? (
          <SkeletonRows rows={8} columns={5} />
        ) : rows.length === 0 ? (
          <Empty
            icon={Target}
            title="No raw findings"
            description="Discovery jobs (subdomain enumeration, port scan, certificate transparency, httpx probe) emit findings as they discover assets. Promote each into the registry, or dismiss if unrelated."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[120px]">
                    Asset type
                  </Th>
                  <Th align="left">Value</Th>
                  <Th align="left" className="w-[120px]">
                    Discovered via
                  </Th>
                  <Th align="left" className="w-[100px]">
                    Confidence
                  </Th>
                  <Th align="left" className="w-[100px]">
                    State
                  </Th>
                  <Th align="left" className="w-[110px]">
                    Found
                  </Th>
                  <Th align="right" className="pr-4 w-[160px]">
                    Actions
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <FindingRow
                    key={f.id}
                    f={f}
                    onPromote={() => setPromoteTarget(f)}
                    onDismiss={() => dismiss(f)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!loading && rows.length > 0 ? (
          <PaginationFooter
            total={total}
            limit={PAGE_LIMIT}
            offset={offset}
            shown={rows.length}
            onPrev={() => setOffset((o) => Math.max(0, o - PAGE_LIMIT))}
            onNext={() => setOffset((o) => o + PAGE_LIMIT)}
          />
        ) : null}
      </Section>

      {promoteTarget ? (
        <PromoteModal
          target={promoteTarget}
          onClose={() => setPromoteTarget(null)}
          onSubmit={() => promote(promoteTarget)}
        />
      ) : null}
    </div>
  );
}

function FindingRow({
  f,
  onPromote,
  onDismiss,
}: {
  f: EasmFindingResponse;
  onPromote: () => void;
  onDismiss: () => void;
}) {
  const [hovered, setHovered] = useState(false);
  const [promHov, setPromHov] = useState(false);
  const [dismissHov, setDismissHov] = useState(false);
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
          {f.asset_type.toUpperCase()}
        </span>
      </td>
      <td style={{ padding: "0 12px", fontFamily: "monospace", fontSize: "12.5px", color: "var(--color-ink)", maxWidth: "420px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {f.value}
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11px", color: "var(--color-body)" }}>
        {f.discovered_via || "—"}
      </td>
      <td className="px-3">
        <ConfidenceCell value={f.confidence} />
      </td>
      <td className="px-3">
        <StatePill
          label={f.state}
          tone={STATE_TONE[f.state] || "neutral"}
        />
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(f.created_at)}
      </td>
      <td className="pr-4">
        <div className="flex items-center justify-end gap-1">
          {f.state === "new" ? (
            <>
              <button
                onClick={onPromote}
                onMouseEnter={() => setPromHov(true)}
                onMouseLeave={() => setPromHov(false)}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "4px",
                  height: "28px",
                  padding: "0 8px",
                  borderRadius: "4px",
                  border: "1px solid rgba(0,167,111,0.4)",
                  background: promHov ? "rgba(0,167,111,0.1)" : "transparent",
                  color: "#007B55",
                  fontSize: "11px",
                  fontWeight: 700,
                  cursor: "pointer",
                  transition: "background 0.15s",
                }}
              >
                <Check style={{ width: "12px", height: "12px" }} />
                PROMOTE
              </button>
              <button
                onClick={onDismiss}
                onMouseEnter={() => setDismissHov(true)}
                onMouseLeave={() => setDismissHov(false)}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "4px",
                  height: "28px",
                  padding: "0 8px",
                  borderRadius: "4px",
                  border: "1px solid var(--color-border)",
                  background: dismissHov ? "var(--color-surface-muted)" : "transparent",
                  color: "var(--color-body)",
                  fontSize: "11px",
                  fontWeight: 700,
                  cursor: "pointer",
                  transition: "background 0.15s",
                }}
              >
                <X style={{ width: "12px", height: "12px" }} />
                DISMISS
              </button>
            </>
          ) : (
            <span style={{ fontSize: "11px", color: "var(--color-muted)", fontFamily: "monospace" }}>
              —
            </span>
          )}
        </div>
      </td>
    </tr>
  );
}

function ConfidenceCell({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value));
  const fillColor =
    pct >= 0.85 ? "#007B55" : pct >= 0.6 ? "#00B8D9" : "#FFAB00";
  return (
    <div className="flex items-center gap-1.5">
      <div style={{ width: "40px", height: "4px", borderRadius: "9999px", background: "var(--color-surface-muted)", overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct * 100}%`, background: fillColor }} />
      </div>
      <span style={{ fontFamily: "monospace", fontSize: "11px", color: "var(--color-body)" }}>
        {pct.toFixed(2)}
      </span>
    </div>
  );
}

function PromoteModal({
  target,
  onClose,
  onSubmit,
}: {
  target: EasmFindingResponse;
  onClose: () => void;
  onSubmit: () => void;
}) {
  return (
    <ModalShell title="Promote finding to asset" onClose={onClose}>
      <div className="p-6 space-y-4">
        <p style={{ fontSize: "13px", color: "var(--color-body)" }}>
          This will create an Asset Registry row for{" "}
          <span style={{ fontFamily: "monospace", fontWeight: 700 }}>{target.value}</span> as a{" "}
          <span style={{ fontFamily: "monospace", fontWeight: 700 }}>{target.asset_type}</span>.
          Subsequent scans will treat it as monitored surface.
        </p>
        <Field label="Confidence" hint="From the discovering scanner.">
          <div style={{ fontFamily: "monospace", fontSize: "14px", fontWeight: 700, color: "var(--color-ink)" }}>
            {target.confidence.toFixed(2)}
          </div>
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={onSubmit}
        submitLabel="Promote"
      />
    </ModalShell>
  );
}
