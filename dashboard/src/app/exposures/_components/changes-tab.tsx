"use client";

import { useCallback, useEffect, useState } from "react";
import { ChevronRight, GitBranch } from "lucide-react";
import { api, type EasmChangeResponse } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  PaginationFooter,
  Section,
  SkeletonRows,
  SevPill,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { useExposuresContext } from "./use-exposures-context";

const PAGE_LIMIT = 50;

export function ChangesTab() {
  const { orgId } = useExposuresContext();
  const { toast } = useToast();
  const [rows, setRows] = useState<EasmChangeResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const { data, page } = await api.easm.listChanges({
        organization_id: orgId,
        limit: PAGE_LIMIT,
      });
      setRows(data);
      setTotal(page.total ?? data.length);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load changes",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-4">
      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={4} />
        ) : rows.length === 0 ? (
          <Empty
            icon={GitBranch}
            title="No asset changes recorded"
            description="As the EASM workers re-scan the surface, every diff (new subdomain, port opens, TLS downgrade, certificate rotation) records here in newest-first order."
          />
        ) : (
          <ul>
            {rows.map((c) => (
              <ChangeRow
                key={c.id}
                change={c}
                expanded={expanded === c.id}
                onToggle={() =>
                  setExpanded((cur) => (cur === c.id ? null : c.id))
                }
              />
            ))}
          </ul>
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
    </div>
  );
}

function ChangeRow({
  change,
  expanded,
  onToggle,
}: {
  change: EasmChangeResponse;
  expanded: boolean;
  onToggle: () => void;
}) {
  const [hov, setHov] = useState(false);
  return (
    <li style={{ borderBottom: "1px solid var(--color-border)" }}>
      <button
        onClick={onToggle}
        onMouseEnter={() => setHov(true)}
        onMouseLeave={() => setHov(false)}
        style={{
          width: "100%",
          padding: "12px 16px",
          display: "flex",
          alignItems: "center",
          gap: "12px",
          textAlign: "left",
          background: hov ? "var(--color-surface)" : "transparent",
          border: "none",
          cursor: "pointer",
          transition: "background 0.15s",
        }}
      >
        <SevPill severity={change.severity} size="sm" />
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
          {change.kind.replace(/_/g, " ").toUpperCase()}
        </span>
        <span style={{ fontSize: "13px", color: "var(--color-ink)", flex: 1 }} className="line-clamp-1">
          {change.summary}
        </span>
        <span style={{ fontFamily: "monospace", fontSize: "11px", color: "var(--color-muted)", flexShrink: 0 }}>
          {timeAgo(change.detected_at)}
        </span>
        <ChevronRight
          style={{
            width: "16px",
            height: "16px",
            color: "var(--color-muted)",
            transform: expanded ? "rotate(90deg)" : "none",
            transition: "transform 0.15s",
          }}
        />
      </button>
      {expanded ? (
        <div
          className="grid grid-cols-2 gap-4 px-4 pb-4 pt-1"
          style={{ background: "var(--color-surface)", borderTop: "1px solid var(--color-border)" }}
        >
          <DiffPanel label="Before" data={change.before} />
          <DiffPanel label="After" data={change.after} />
        </div>
      ) : null}
    </li>
  );
}

function DiffPanel({
  label,
  data,
}: {
  label: string;
  data: Record<string, unknown> | null;
}) {
  return (
    <div>
      <div style={{ fontSize: "10.5px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "var(--color-muted)", marginBottom: "6px" }}>
        {label}
      </div>
      <pre style={{
        fontSize: "11.5px",
        fontFamily: "monospace",
        color: "var(--color-ink)",
        background: "var(--color-canvas)",
        border: "1px solid var(--color-border)",
        borderRadius: "4px",
        padding: "8px",
        maxHeight: "200px",
        overflow: "auto",
        whiteSpace: "pre-wrap",
        wordBreak: "break-all",
      }}>
        {data ? JSON.stringify(data, null, 2) : <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>empty</span>}
      </pre>
    </div>
  );
}
