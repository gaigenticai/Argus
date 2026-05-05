"use client";

import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CircleCheck,
  CircleDashed,
  CircleX,
  Compass,
  Loader2,
  PlayCircle,
  Shield,
  Sparkles,
} from "lucide-react";
import {
  api,
  type HuntDetail,
  type HuntFinding,
  type HuntListItem,
  type HuntStatus,
} from "@/lib/api";
import {
  Empty,
  PageHeader,
  RefreshButton,
  Section,
  SkeletonRows,
  Th,
} from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";
import { CoverageGate } from "@/components/shared/coverage-gate";


export default function ThreatHunterPage() {
  const { toast } = useToast();
  const [rows, setRows] = useState<HuntListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<HuntDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  const loadList = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.threatHunts.list({ limit: 50 });
      setRows(data);
      if (data.length > 0 && !selectedId) {
        setSelectedId(data[0].id);
      }
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load hunts",
      );
    } finally {
      setLoading(false);
    }
  }, [selectedId, toast]);

  const loadDetail = useCallback(
    async (id: string) => {
      try {
        const d = await api.threatHunts.get(id);
        setDetail(d);
      } catch (e) {
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load hunt",
        );
      }
    },
    [toast],
  );

  useEffect(() => {
    void loadList();
  }, [loadList]);

  useEffect(() => {
    if (selectedId) void loadDetail(selectedId);
  }, [selectedId, loadDetail]);

  const handleRun = useCallback(async (templateId?: string) => {
    setRunning(true);
    try {
      await api.threatHunts.create(templateId);
      toast("info", "Hunt dispatched — give it a minute");
      await loadList();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to start hunt",
      );
    } finally {
      setRunning(false);
    }
  }, [loadList, toast]);

  return (
    <CoverageGate pageSlug="threat-hunter" pageLabel="Threat Hunter">
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Sparkles, label: "Agentic" }}
        title="Threat Hunter"
        description={
          "Weekly autonomous hunt — picks an active threat-actor cluster, " +
          "cross-checks their TTPs against your open exposures, recent " +
          "alerts, and tracked IOCs, then surfaces the gaps. The schedule " +
          "runs in the worker; you can also kick off an ad-hoc hunt below."
        }
        actions={
          <>
            <TemplatesButton onPicked={handleRun} />
            <RunHuntButton onClick={handleRun} running={running} />
            <RefreshButton onClick={loadList} refreshing={loading} />
          </>
        }
      />

      {detail && detail.findings && detail.findings.length > 0 && (
        <DetailActionBar
          detail={detail}
          onRefresh={() => selectedId && void loadDetail(selectedId)}
        />
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <Section className="lg:col-span-5">
          <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--color-border)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>Past hunts</h3>
            <span style={{ fontSize: "11px", color: "var(--color-muted)" }}>{rows.length} total</span>
          </div>
          {loading ? (
            <SkeletonRows rows={6} columns={3} />
          ) : rows.length === 0 ? (
            <Empty
              icon={Compass}
              title="No hunts yet"
              description={
                "The first scheduled hunt runs once the worker has been " +
                "up for a tick. Click 'Run hunt now' to kick one off " +
                "immediately."
              }
            />
          ) : (
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[110px]">
                    Status
                  </Th>
                  <Th align="left">Focus actor</Th>
                  <Th align="right" className="pr-4 w-[100px]">
                    Started
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <HuntRow
                    key={r.id}
                    r={r}
                    isActive={r.id === selectedId}
                    onClick={() => setSelectedId(r.id)}
                  />
                ))}
              </tbody>
            </table>
          )}
        </Section>

        <div className="lg:col-span-7">
          {detail ? (
            <HuntDetailPanel detail={detail} />
          ) : (
            <Section>
              <Empty
                icon={Sparkles}
                title="Select a hunt"
                description="Click a row on the left to see findings, MITRE coverage, and the trace."
              />
            </Section>
          )}
        </div>
      </div>
    </div>
      </CoverageGate>
  );
}

function RunHuntButton({ onClick, running }: { onClick: () => void; running: boolean }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={running}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        height: "40px",
        padding: "0 16px",
        borderRadius: "4px",
        border: "none",
        background: running ? "var(--color-surface-muted)" : hov ? "#e64600" : "var(--color-accent)",
        color: running ? "var(--color-muted)" : "var(--color-on-dark)",
        fontSize: "13px",
        fontWeight: 700,
        cursor: running ? "not-allowed" : "pointer",
        transition: "background 0.15s",
        opacity: running ? 0.7 : 1,
      }}
    >
      {running ? (
        <Loader2 style={{ width: "16px", height: "16px" }} className="animate-spin" />
      ) : (
        <PlayCircle style={{ width: "16px", height: "16px" }} />
      )}
      Run hunt now
    </button>
  );
}

function HuntRow({
  r,
  isActive,
  onClick,
}: {
  r: HuntListItem;
  isActive: boolean;
  onClick: () => void;
}) {
  const [hov, setHov] = useState(false);
  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: isActive ? "rgba(0,187,217,0.07)" : hov ? "var(--color-surface)" : "transparent",
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <td className="pl-4">
        <StatusPill status={r.status} />
      </td>
      <td className="px-3" style={{ fontSize: "13px", color: "var(--color-body)" }}>
        {r.primary_actor_alias ?? (
          <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>n/a</span>
        )}
      </td>
      <td className="pr-4" style={{ textAlign: "right", fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(r.created_at)}
      </td>
    </tr>
  );
}

function StatusPill({ status }: { status: HuntStatus }) {
  const Icon = {
    queued: CircleDashed,
    running: Loader2,
    completed: CircleCheck,
    failed: CircleX,
  }[status];

  const styleMap: Record<HuntStatus, React.CSSProperties> = {
    completed: { background: "rgba(0,167,111,0.1)", color: "#007B55" },
    running: { background: "rgba(0,187,217,0.1)", color: "#007B8A" },
    queued: { background: "var(--color-surface-muted)", color: "var(--color-body)" },
    failed: { background: "rgba(255,86,48,0.08)", color: "#B71D18" },
  };

  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: "6px",
      height: "22px",
      padding: "0 8px",
      borderRadius: "4px",
      fontSize: "11px",
      fontWeight: 700,
      textTransform: "uppercase",
      letterSpacing: "0.06em",
      ...styleMap[status],
    }}>
      <Icon style={{ width: "12px", height: "12px" }} className={status === "running" ? "animate-spin" : undefined} />
      {status}
    </span>
  );
}


function HuntDetailPanel({ detail }: { detail: HuntDetail }) {
  return (
    <Section>
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--color-border)", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px" }}>
        <div className="min-w-0">
          <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)", display: "inline-flex", alignItems: "center", gap: "8px" }}>
            <Shield style={{ width: "14px", height: "14px" }} />
            {detail.primary_actor_alias ?? "Hunt"} · {detail.id.slice(0, 8)}…
          </h3>
          <p style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "2px" }}>
            {detail.iterations} step{detail.iterations === 1 ? "" : "s"}
            {detail.model_id ? ` · ${detail.model_id}` : ""}
            {detail.duration_ms ? ` · ${(detail.duration_ms / 1000).toFixed(1)}s` : ""}
            {detail.confidence !== null
              ? ` · confidence ${detail.confidence.toFixed(2)}`
              : ""}
          </p>
        </div>
        <StatusPill status={detail.status} />
      </div>

      <div className="p-5 space-y-5">
        {detail.status === "failed" && detail.error_message ? (
          <div style={{ borderRadius: "5px", border: "1px solid rgba(255,86,48,0.4)", background: "rgba(255,86,48,0.08)", padding: "12px 16px", fontFamily: "monospace", fontSize: "12.5px", color: "#B71D18" }}>
            {detail.error_message}
          </div>
        ) : null}

        {detail.summary ? (
          <section>
            <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>
              Summary
            </h4>
            <p style={{ fontSize: "13.5px", lineHeight: 1.55, color: "var(--color-body)" }}>
              {detail.summary}
            </p>
          </section>
        ) : null}

        {detail.findings && detail.findings.length > 0 ? (
          <section>
            <h4 style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", marginBottom: "8px" }}>
              Findings · {detail.findings.length}
            </h4>
            <ol className="space-y-3">
              {detail.findings.map((f, i) => (
                <FindingCard key={i} finding={f} />
              ))}
            </ol>
          </section>
        ) : detail.status === "completed" ? (
          <section style={{ borderRadius: "5px", border: "1px solid rgba(0,167,111,0.4)", background: "rgba(0,167,111,0.08)", padding: "12px 16px", display: "flex", alignItems: "flex-start", gap: "12px" }}>
            <CircleCheck style={{ width: "20px", height: "20px", marginTop: "2px", color: "#007B55", flexShrink: 0 }} />
            <div>
              <p style={{ fontSize: "13px", fontWeight: 700, color: "#007B55" }}>
                Surface looks clean against this actor
              </p>
              <p style={{ fontSize: "12.5px", color: "var(--color-body)", marginTop: "4px" }}>
                The agent ran the cross-checks and didn't surface any gaps
                worth raising. The hunt history above is the audit trail.
              </p>
            </div>
          </section>
        ) : null}
      </div>
    </Section>
  );
}


function FindingCard({ finding }: { finding: HuntFinding }) {
  const borderColor =
    finding.relevance >= 0.8
      ? "rgba(255,86,48,0.4)"
      : finding.relevance >= 0.6
        ? "rgba(255,171,0,0.4)"
        : "var(--color-border)";
  const bgColor =
    finding.relevance >= 0.8
      ? "rgba(255,86,48,0.08)"
      : finding.relevance >= 0.6
        ? "rgba(255,171,0,0.08)"
        : "var(--color-surface)";
  const iconColor =
    finding.relevance >= 0.8
      ? "#B71D18"
      : finding.relevance >= 0.6
        ? "#B76E00"
        : "var(--color-muted)";

  return (
    <li style={{ borderRadius: "5px", border: `1px solid ${borderColor}`, background: bgColor, padding: "12px 16px", display: "flex", alignItems: "flex-start", gap: "12px" }}>
      <AlertTriangle style={{ width: "16px", height: "16px", marginTop: "2px", flexShrink: 0, color: iconColor }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap" }}>
          <span style={{ fontSize: "13.5px", fontWeight: 700, color: "var(--color-ink)" }}>
            {finding.title}
          </span>
          <span style={{ fontSize: "10.5px", fontFamily: "monospace", color: "var(--color-muted)" }}>
            relevance {finding.relevance.toFixed(2)}
          </span>
        </div>
        <p style={{ fontSize: "13px", color: "var(--color-body)", marginTop: "4px", lineHeight: 1.55 }}>
          {finding.description}
        </p>
        {finding.mitre_ids.length > 0 ? (
          <div style={{ marginTop: "8px", display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
            {finding.mitre_ids.map((id) => (
              <span
                key={id}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  height: "20px",
                  padding: "0 6px",
                  borderRadius: "4px",
                  background: "rgba(0,187,217,0.1)",
                  color: "#007B8A",
                  fontSize: "10.5px",
                  fontFamily: "monospace",
                  fontWeight: 700,
                }}
              >
                {id}
              </span>
            ))}
          </div>
        ) : null}
        {finding.recommended_action ? (
          <p style={{ marginTop: "8px", fontSize: "12.5px", color: "var(--color-body)" }}>
            <span style={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", fontSize: "10.5px", color: "var(--color-muted)" }}>
              Action
            </span>{" "}
            — {finding.recommended_action}
          </p>
        ) : null}
      </div>
    </li>
  );
}


function TemplatesButton({ onPicked }: { onPicked: (templateId?: string) => void }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [templates, setTemplates] = useState<Awaited<ReturnType<typeof api.threatHunts.listTemplates>>>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    api.threatHunts.listTemplates()
      .then(setTemplates)
      .catch(() => toast("error", "Failed to load templates"))
      .finally(() => setLoading(false));
  }, [open, toast]);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "8px",
          height: "40px",
          padding: "0 14px",
          borderRadius: "4px",
          border: "1px solid var(--color-border)",
          background: "var(--color-canvas)",
          color: "var(--color-body)",
          fontSize: "13px",
          fontWeight: 700,
          cursor: "pointer",
        }}
      >
        Templates
      </button>
      {open && (
        <div
          className="absolute right-0 top-full mt-1 z-50 w-[420px] p-2"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 6,
            boxShadow: "0 8px 24px rgba(0,0,0,0.10)",
          }}
        >
          <div className="flex items-center justify-between mb-2 px-2 pt-1">
            <h4 className="text-[12px] font-bold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              Hunt templates (PEAK)
            </h4>
            <button
              onClick={async () => {
                try {
                  const r = await api.threatHunts.seedTemplates();
                  toast("success", `Seeded ${r.inserted} templates (refreshed ${r.updated})`);
                  const fresh = await api.threatHunts.listTemplates();
                  setTemplates(fresh);
                } catch (e) {
                  toast("error", `Seed failed — ${String(e)}`);
                }
              }}
              className="text-[11px] font-semibold"
              style={{ color: "var(--color-accent)" }}
            >
              Reseed builtins
            </button>
          </div>
          {loading ? (
            <p className="text-[12px] px-2 py-3" style={{ color: "var(--color-muted)" }}>Loading…</p>
          ) : templates.length === 0 ? (
            <p className="text-[12px] px-2 py-3" style={{ color: "var(--color-muted)" }}>No templates — click Reseed.</p>
          ) : (
            <div className="space-y-1 max-h-[480px] overflow-y-auto">
              {templates.map((t) => (
                <button
                  key={t.id}
                  onClick={async () => {
                    setOpen(false);
                    onPicked(t.id);
                    toast("info", `Hunt queued — anchored on template "${t.name}"`);
                  }}
                  className="block w-full text-left p-2"
                  style={{
                    borderRadius: 4,
                    background: "transparent",
                    border: "1px solid transparent",
                  }}
                  onMouseEnter={(e) => {
                    (e.currentTarget as HTMLElement).style.borderColor = "var(--color-border)";
                    (e.currentTarget as HTMLElement).style.background = "var(--color-surface)";
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLElement).style.borderColor = "transparent";
                    (e.currentTarget as HTMLElement).style.background = "transparent";
                  }}
                >
                  <div className="text-[12px] font-semibold" style={{ color: "var(--color-ink)" }}>{t.name}</div>
                  <div className="text-[11px] mt-0.5" style={{ color: "var(--color-muted)" }}>{t.hypothesis}</div>
                  <div className="flex gap-1 mt-1">
                    {t.mitre_technique_ids.map((m) => (
                      <span
                        key={m}
                        className="px-1.5 h-[16px] inline-flex items-center text-[10px] font-bold"
                        style={{ borderRadius: 3, background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function DetailActionBar({
  detail,
  onRefresh,
}: {
  detail: HuntDetail;
  onRefresh: () => void;
}) {
  const { toast } = useToast();
  return (
    <div
      className="flex items-center gap-2 p-3"
      style={{
        background: "var(--color-surface)",
        border: "1px solid var(--color-border)",
        borderRadius: 5,
      }}
    >
      <span className="text-[12px] font-semibold mr-2" style={{ color: "var(--color-muted)" }}>
        Workflow: {(detail as HuntDetail & { workflow_state?: string }).workflow_state ?? "hypothesis"}
      </span>
      {(["hypothesis", "investigating", "reporting", "closed"] as const).map((s) => (
        <button
          key={s}
          onClick={async () => {
            try {
              await api.threatHunts.transition(detail.id, s);
              toast("success", `Moved to "${s}"`);
              onRefresh();
            } catch (e) {
              toast("error", `Transition failed — ${String(e)}`);
            }
          }}
          className="h-7 px-2 text-[11px] font-semibold"
          style={{
            borderRadius: 3,
            border: "1px solid var(--color-border)",
            background: "var(--color-canvas)",
            color: "var(--color-body)",
          }}
        >
          → {s}
        </button>
      ))}
      <button
        onClick={async () => {
          try {
            const r = await api.threatHunts.escalate(detail.id);
            toast("success", `Case created — ${r.title}`);
          } catch (e) {
            toast("error", `Escalate failed — ${String(e)}`);
          }
        }}
        className="h-7 px-3 text-[11px] font-semibold"
        style={{ borderRadius: 3, background: "var(--color-accent)", color: "#fff" }}
      >
        Escalate to case
      </button>
      <button
        onClick={async () => {
          try {
            const r = await api.threatHunts.report(detail.id);
            const blob = new Blob([r.markdown], { type: "text/markdown" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `hunt-${detail.id}.md`;
            a.click();
            URL.revokeObjectURL(url);
          } catch (e) {
            toast("error", `Report failed — ${String(e)}`);
          }
        }}
        className="h-7 px-3 text-[11px] font-semibold ml-auto"
        style={{
          borderRadius: 3,
          border: "1px solid var(--color-border)",
          background: "var(--color-canvas)",
          color: "var(--color-body)",
        }}
      >
        Download report (md)
      </button>
    </div>
  );
}
