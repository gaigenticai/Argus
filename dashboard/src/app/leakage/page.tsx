"use client";

import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CreditCard,
  ExternalLink,
  Lock,
  Plus,
  ShieldAlert,
  TestTube,
  Trash2,
} from "lucide-react";
import {
  api,
  type BinResponse,
  type CardLeakageResponse,
  type DlpFindingResponse,
  type DlpPolicyResponse,
  type Org,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Field,
  ModalFooter,
  ModalShell,
  OrgSwitcher,
  PageHeader,
  RefreshButton,
  Section,
  Select,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";

const SEVERITY_TONE: Record<string, StateTone> = {
  critical: "error-strong",
  high: "error",
  medium: "warning",
  low: "info",
  info: "muted",
};

const STATE_TONE: Record<string, StateTone> = {
  open: "neutral",
  confirmed: "error-strong",
  remediated: "success",
  false_positive: "muted",
  acknowledged: "info",
  dismissed: "muted",
};

const TABS = ["dlp", "cards", "policies", "bins"] as const;
type TabId = (typeof TABS)[number];

const inputStyle: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  outline: "none",
};

export default function LeakagePage() {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [tab, setTab] = useState<TabId>(() => {
    if (typeof window === "undefined") return "dlp";
    const h = window.location.hash.replace("#", "");
    return ((TABS as readonly string[]).includes(h) ? h : "dlp") as TabId;
  });
  const [refreshKey, setRefreshKey] = useState(0);
  const refresh = () => setRefreshKey((k) => k + 1);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const list = await api.getOrgs();
        if (!alive) return;
        setOrgs(list);
        const persisted = localStorage.getItem("argus_org_id");
        const initial =
          (persisted && list.find((o) => o.id === persisted)?.id) ||
          list[0]?.id ||
          "";
        setOrgIdState(initial);
      } catch (e) {
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load organizations",
        );
      }
    })();
    return () => {
      alive = false;
    };
  }, [toast]);

  const setOrgId = useCallback((id: string) => {
    setOrgIdState(id);
    localStorage.setItem("argus_org_id", id);
  }, []);

  const switchTab = (next: TabId) => {
    setTab(next);
    const url = new URL(window.location.href);
    url.hash = next === "dlp" ? "" : next;
    window.history.replaceState(null, "", url.toString());
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Lock, label: "Governance" }}
        title="DLP & Card Leakage"
        description="Customer-supplied DLP regex policies plus a BIN-aware credit-card detector. Findings auto-promote to Cases at HIGH+ via the existing auto-link helper."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
            <RefreshButton onClick={refresh} refreshing={false} />
          </>
        }
      />

      <div className="flex items-center gap-1 -mx-1" style={{ borderBottom: "1px solid var(--color-border)" }}>
        {(
          [
            ["dlp", "DLP findings", ShieldAlert],
            ["cards", "Card leakage", CreditCard],
            ["policies", "DLP policies", Lock],
            ["bins", "BIN registry", CreditCard],
          ] as const
        ).map(([id, label, Icon]) => {
          const active = tab === id;
          return (
            <button
              key={id}
              onClick={() => switchTab(id as TabId)}
              className="relative h-10 px-3.5 flex items-center gap-2 text-[13px] font-bold whitespace-nowrap transition-colors"
              style={{
                color: active ? "var(--color-ink)" : "var(--color-muted)",
                boxShadow: active ? "rgb(255, 79, 0) 0px -3px 0px 0px inset" : "none",
              }}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
            </button>
          );
        })}
      </div>

      <div key={`${orgId}-${tab}-${refreshKey}`}>
        {tab === "dlp" && <DlpFindingsTab orgId={orgId} />}
        {tab === "cards" && <CardLeakageTab orgId={orgId} />}
        {tab === "policies" && (
          <DlpPoliciesTab orgId={orgId} onChange={refresh} />
        )}
        {tab === "bins" && <BinRegistryTab orgId={orgId} />}
      </div>
    </div>
  );
}

function DlpFindingsTab({ orgId }: { orgId: string }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<DlpFindingResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [stateFilter, setStateFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const data = await api.leakage.listDlpFindings({
        organization_id: orgId,
        state: stateFilter === "all" ? undefined : stateFilter,
        severity: severityFilter === "all" ? undefined : severityFilter,
        limit: 200,
      });
      setRows(data);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load DLP findings",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, stateFilter, severityFilter, toast]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="State"
          value={stateFilter}
          options={[
            { value: "all", label: "Any state" },
            { value: "open", label: "Open" },
            { value: "confirmed", label: "Confirmed" },
            { value: "remediated", label: "Remediated" },
            { value: "false_positive", label: "False +ve" },
          ]}
          onChange={setStateFilter}
        />
        <Select
          ariaLabel="Severity"
          value={severityFilter}
          options={[
            { value: "all", label: "Any severity" },
            { value: "critical", label: "Critical" },
            { value: "high", label: "High" },
            { value: "medium", label: "Medium" },
            { value: "low", label: "Low" },
          ]}
          onChange={setSeverityFilter}
        />
      </div>
      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={5} />
        ) : rows.length === 0 ? (
          <Empty
            icon={ShieldAlert}
            title="No DLP findings"
            description="DLP findings are created when a regex policy fires against ingested content (Telegram, news articles, public-page snapshots)."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[110px]">
                    Severity
                  </Th>
                  <Th align="left">Policy</Th>
                  <Th align="left">Source</Th>
                  <Th align="left" className="w-[80px]">
                    Matches
                  </Th>
                  <Th align="left" className="w-[110px]">
                    State
                  </Th>
                  <Th align="right" className="pr-4 w-[100px]">
                    Detected
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.id}
                    className="h-12 transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  >
                    <td className="pl-4">
                      <StatePill
                        label={r.severity}
                        tone={SEVERITY_TONE[r.severity] || "neutral"}
                      />
                    </td>
                    <td className="px-3">
                      <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                        {r.policy_name}
                      </div>
                      {r.matched_excerpts.length > 0 ? (
                        <div className="text-[11px] font-mono line-clamp-1 mt-0.5" style={{ color: "var(--color-muted)" }}>
                          {r.matched_excerpts[0]}
                        </div>
                      ) : null}
                    </td>
                    <td className="px-3 font-mono text-[12px] max-w-[280px] truncate" style={{ color: "var(--color-body)" }}>
                      {r.source_url ? (
                        <a
                          href={r.source_url}
                          target="_blank"
                          rel="noopener noreferrer nofollow"
                          className="inline-flex items-center gap-1 transition-colors"
                          style={{ color: "var(--color-body)" }}
                          onMouseEnter={e => (e.currentTarget.style.color = "var(--color-accent)")}
                          onMouseLeave={e => (e.currentTarget.style.color = "var(--color-body)")}
                        >
                          {r.source_url}
                          <ExternalLink className="w-3 h-3" style={{ color: "var(--color-muted)" }} />
                        </a>
                      ) : (
                        <span className="italic" style={{ color: "var(--color-muted)" }}>none</span>
                      )}
                    </td>
                    <td className="px-3 font-mono text-[13px] tabular-nums font-bold" style={{ color: "var(--color-ink)" }}>
                      {r.matched_count}
                    </td>
                    <td className="px-3">
                      <StatePill
                        label={r.state}
                        tone={STATE_TONE[r.state] || "neutral"}
                      />
                    </td>
                    <td className="pr-4 text-right font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                      {timeAgo(r.detected_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}

function CardLeakageTab({ orgId }: { orgId: string }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<CardLeakageResponse[]>([]);
  const [binCount, setBinCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const [findings, bins] = await Promise.all([
        api.leakage.listCardFindings({
          organization_id: orgId,
          limit: 200,
        }),
        api.leakage.listBins(orgId),
      ]);
      setRows(findings);
      setBinCount(bins.length);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load card findings",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const binRegistryEmpty = binCount !== null && binCount === 0;

  return (
    <div className="space-y-4">
      {binRegistryEmpty ? (
        <div
          role="alert"
          className="flex items-start gap-3 px-4 py-3"
          style={{ borderRadius: "5px", border: "1px solid rgba(255,171,0,0.4)", background: "rgba(255,171,0,0.08)" }}
        >
          <AlertTriangle className="w-5 h-5 mt-0.5 shrink-0" style={{ color: "#B76E00" }} />
          <div className="flex-1">
            <p className="text-[13px] font-bold" style={{ color: "#B76E00" }}>
              BIN registry is empty — card-leakage detection is high-noise
            </p>
            <p className="text-[12.5px] mt-0.5" style={{ color: "var(--color-body)" }}>
              Without registered issuer prefixes the detector falls back to
              Luhn-only validation, which has a high false-positive rate
              (sequences like <code className="font-mono">1111-1111-1111-1111</code>{" "}
              pass Luhn). Import your bank&apos;s BIN ranges via{" "}
              <code className="font-mono">POST /leakage/bins/import</code> to
              scope detections to your real card portfolio.
            </p>
          </div>
        </div>
      ) : null}

      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={6} />
        ) : rows.length === 0 ? (
          <Empty
            icon={CreditCard}
            title="No card leakage findings"
            description="Card findings are created when ingested content matches a registered BIN with a Luhn-valid PAN. Add BINs in the BIN registry tab to widen detection."
          />
        ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                <Th align="left" className="pl-4">
                  PAN
                </Th>
                <Th align="left">Issuer / scheme</Th>
                <Th align="left">Source</Th>
                <Th align="left" className="w-[80px]">
                  Type
                </Th>
                <Th align="left" className="w-[110px]">
                  State
                </Th>
                <Th align="right" className="pr-4 w-[100px]">
                  Detected
                </Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r.id}
                  className="h-12 transition-colors"
                  style={{ borderBottom: "1px solid var(--color-border)" }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                >
                  <td className="pl-4 font-mono text-[12.5px] tabular-nums" style={{ color: "var(--color-ink)" }}>
                    {r.pan_first6}
                    <span style={{ color: "var(--color-muted)" }}>······</span>
                    {r.pan_last4}
                  </td>
                  <td className="px-3 text-[12.5px]" style={{ color: "var(--color-body)" }}>
                    {r.issuer || (
                      <span className="italic" style={{ color: "var(--color-muted)" }}>unknown</span>
                    )}
                    <span className="ml-1.5 text-[10.5px] font-bold uppercase tracking-[0.06em]" style={{ color: "var(--color-muted)" }}>
                      {r.scheme}
                    </span>
                  </td>
                  <td className="px-3 font-mono text-[12px] max-w-[280px] truncate" style={{ color: "var(--color-body)" }}>
                    {r.source_url ? (
                      <a
                        href={r.source_url}
                        target="_blank"
                        rel="noopener noreferrer nofollow"
                        className="inline-flex items-center gap-1 transition-colors"
                        style={{ color: "var(--color-body)" }}
                        onMouseEnter={e => (e.currentTarget.style.color = "var(--color-accent)")}
                        onMouseLeave={e => (e.currentTarget.style.color = "var(--color-body)")}
                      >
                        {r.source_url}
                        <ExternalLink className="w-3 h-3" style={{ color: "var(--color-muted)" }} />
                      </a>
                    ) : (
                      <span className="italic" style={{ color: "var(--color-muted)" }}>none</span>
                    )}
                  </td>
                  <td className="px-3">
                    <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]" style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}>
                      {r.card_type.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-3">
                    <StatePill
                      label={r.state}
                      tone={STATE_TONE[r.state] || "neutral"}
                    />
                  </td>
                  <td className="pr-4 text-right font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                    {timeAgo(r.detected_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        )}
      </Section>
    </div>
  );
}

function DlpPoliciesTab({
  orgId,
  onChange,
}: {
  orgId: string;
  onChange: () => void;
}) {
  const { toast } = useToast();
  const [rows, setRows] = useState<DlpPolicyResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [testing, setTesting] = useState<DlpPolicyResponse | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      setRows(await api.leakage.listDlpPolicies(orgId));
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load DLP policies",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const remove = async (p: DlpPolicyResponse) => {
    if (!confirm(`Delete DLP policy "${p.name}"?`)) return;
    try {
      await api.leakage.deleteDlpPolicy(p.id);
      toast("success", "Policy deleted");
      onChange();
      load();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Delete failed");
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[12px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
          {rows.length} polic{rows.length === 1 ? "y" : "ies"}
        </p>
        <button
          onClick={() => setShowCreate(true)}
          className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold"
          style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
        >
          <Plus className="w-3.5 h-3.5" />
          New policy
        </button>
      </div>

      <Section>
        {loading ? (
          <SkeletonRows rows={4} columns={5} />
        ) : rows.length === 0 ? (
          <Empty
            icon={Lock}
            title="No DLP policies"
            description="Create regex policies to flag PII, secrets, source-code references in ingested content. Each policy is timeout-bounded by the ReDoS guard (Audit B8)."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[110px]">
                    Severity
                  </Th>
                  <Th align="left">Name</Th>
                  <Th align="left">Pattern</Th>
                  <Th align="left" className="w-[100px]">
                    Kind
                  </Th>
                  <Th align="left" className="w-[100px]">
                    Status
                  </Th>
                  <Th align="right" className="pr-4 w-[140px]">
                    &nbsp;
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((p) => (
                  <tr
                    key={p.id}
                    className="h-12 transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  >
                    <td className="pl-4">
                      <StatePill
                        label={p.severity}
                        tone={SEVERITY_TONE[p.severity] || "neutral"}
                      />
                    </td>
                    <td className="px-3">
                      <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                        {p.name}
                      </div>
                      {p.description ? (
                        <div className="text-[11px] line-clamp-1 mt-0.5" style={{ color: "var(--color-muted)" }}>
                          {p.description}
                        </div>
                      ) : null}
                    </td>
                    <td className="px-3 font-mono text-[11.5px] max-w-[300px] truncate" style={{ color: "var(--color-body)" }}>
                      {p.pattern}
                    </td>
                    <td className="px-3">
                      <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]" style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}>
                        {p.kind.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-3">
                      {p.enabled ? (
                        <StatePill label="ENABLED" tone="success" />
                      ) : (
                        <StatePill label="DISABLED" tone="muted" />
                      )}
                    </td>
                    <td className="pr-4 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setTesting(p)}
                          className="inline-flex items-center gap-1 h-7 px-2 text-[11px] font-bold transition-colors"
                          style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
                          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
                          onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
                        >
                          <TestTube className="w-3 h-3" />
                          TEST
                        </button>
                        <button
                          onClick={() => remove(p)}
                          className="p-1.5 transition-colors"
                          style={{ borderRadius: "4px", color: "var(--color-muted)" }}
                          onMouseEnter={e => { e.currentTarget.style.background = "rgba(255,86,48,0.1)"; e.currentTarget.style.color = "#B71D18"; }}
                          onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--color-muted)"; }}
                          aria-label="Delete"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {showCreate && (
        <CreatePolicyModal
          orgId={orgId}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            load();
            onChange();
          }}
        />
      )}
      {testing && (
        <TestPolicyModal
          policy={testing}
          onClose={() => setTesting(null)}
        />
      )}
    </div>
  );
}

function CreatePolicyModal({
  orgId,
  onClose,
  onCreated,
}: {
  orgId: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [kind, setKind] = useState("regex");
  const [pattern, setPattern] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!name.trim() || !pattern.trim() || busy) return;
    setBusy(true);
    try {
      await api.leakage.createDlpPolicy({
        organization_id: orgId,
        name: name.trim(),
        kind,
        pattern,
        severity,
        description: description.trim() || undefined,
        enabled: true,
      });
      toast("success", `Policy "${name.trim()}" created`);
      onCreated();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Create failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Create DLP policy" onClose={onClose}>
      <div className="p-6 space-y-5">
        <Field label="Name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full h-10 px-3 text-[13px]"
            style={inputStyle}
            placeholder="customer-email-regex"
            autoFocus
          />
        </Field>
        <Field
          label="Pattern"
          required
          hint="Python re. ReDoS-bounded; nested quantifiers are statically rejected."
        >
          <textarea
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            rows={2}
            className="w-full px-3 py-2 text-[13px] font-mono resize-none"
            style={inputStyle}
            placeholder="\\b[A-Za-z0-9._%+-]+@argusbank\\.demo\\b"
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Kind" required>
            <Select
              ariaLabel="Kind"
              value={kind}
              options={[
                { value: "regex", label: "Regex" },
                { value: "literal", label: "Literal" },
              ]}
              onChange={setKind}
            />
          </Field>
          <Field label="Severity" required>
            <Select
              ariaLabel="Severity"
              value={severity}
              options={[
                { value: "critical", label: "Critical" },
                { value: "high", label: "High" },
                { value: "medium", label: "Medium" },
                { value: "low", label: "Low" },
              ]}
              onChange={setSeverity}
            />
          </Field>
        </div>
        <Field label="Description">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="w-full h-10 px-3 text-[13px]"
            style={inputStyle}
            placeholder="What this policy catches and why it matters."
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Creating…" : "Create"}
        disabled={!name.trim() || !pattern.trim() || busy}
      />
    </ModalShell>
  );
}

function TestPolicyModal({
  policy,
  onClose,
}: {
  policy: DlpPolicyResponse;
  onClose: () => void;
}) {
  const { toast } = useToast();
  const [text, setText] = useState("");
  const [result, setResult] = useState<{
    matched: number;
    excerpts: string[];
    duration_ms: number;
  } | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    if (!text.trim() || busy) return;
    setBusy(true);
    try {
      const r = await api.leakage.testDlpPolicy(policy.id, text);
      setResult(r);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Test failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title={`Test ${policy.name}`} onClose={onClose} width={600}>
      <div className="p-6 space-y-5">
        <Field
          label="Pattern"
          hint="Read-only. Edit the policy to change."
        >
          <pre className="px-3 py-2 text-[12px] font-mono overflow-x-auto" style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-surface)", color: "var(--color-body)" }}>
            {policy.pattern}
          </pre>
        </Field>
        <Field label="Sample text" required>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={6}
            className="w-full px-3 py-2 text-[13px] font-mono resize-none"
            style={inputStyle}
            placeholder="Paste content to evaluate against the regex…"
            autoFocus
          />
        </Field>
        {result ? (
          <Section>
            <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: "1px solid var(--color-border)" }}>
              <span className="text-[12px] font-bold uppercase tracking-[0.1em]" style={{ color: "var(--color-body)" }}>
                Result
              </span>
              <span className="font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                {result.duration_ms.toFixed(1)}ms
              </span>
            </div>
            <div className="p-4">
              <div className="flex items-center gap-2 mb-2">
                <span
                  className="font-mono text-[14px] font-extrabold tabular-nums"
                  style={{ color: result.matched > 0 ? "#FF5630" : "#007B55" }}
                >
                  {result.matched}
                </span>
                <span className="text-[12px]" style={{ color: "var(--color-body)" }}>
                  match{result.matched === 1 ? "" : "es"}
                </span>
              </div>
              {result.excerpts.length > 0 ? (
                <ul className="space-y-1">
                  {result.excerpts.map((x, i) => (
                    <li
                      key={i}
                      className="font-mono text-[11.5px] px-2 py-1 truncate"
                      style={{ borderRadius: "4px", border: "1px solid rgba(255,171,0,0.3)", background: "rgba(255,171,0,0.06)", color: "var(--color-body)" }}
                    >
                      {x}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          </Section>
        ) : null}
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={run}
        submitLabel={busy ? "Running…" : "Test"}
        disabled={!text.trim() || busy}
      />
    </ModalShell>
  );
}

function BinRegistryTab({ orgId }: { orgId: string }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<BinResponse[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await api.leakage.listBins(orgId || undefined));
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load BINs",
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
      <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>
        BINs in the registry drive the card-leakage detector — only PANs whose
        prefix matches a registered BIN are flagged. Bulk-import via the
        backend&apos;s <code className="font-mono">POST /leakage/bins/import</code>{" "}
        endpoint with a CSV.
      </p>
      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={5} />
        ) : rows.length === 0 ? (
          <Empty
            icon={CreditCard}
            title="No BINs registered"
            description="Use the bins/import endpoint to upload a CSV with bin_prefix, issuer, scheme, card_type, country_code columns."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[120px]">
                    Prefix
                  </Th>
                  <Th align="left">Issuer</Th>
                  <Th align="left" className="w-[100px]">
                    Scheme
                  </Th>
                  <Th align="left" className="w-[100px]">
                    Type
                  </Th>
                  <Th align="left" className="w-[80px]">
                    Country
                  </Th>
                  <Th align="right" className="pr-4 w-[120px]">
                    Added
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((b) => (
                  <tr
                    key={b.id}
                    className="h-11 transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  >
                    <td className="pl-4 font-mono text-[12.5px] tabular-nums" style={{ color: "var(--color-ink)" }}>
                      {b.bin_prefix}
                    </td>
                    <td className="px-3 text-[12.5px]" style={{ color: "var(--color-body)" }}>
                      {b.issuer || (
                        <span className="italic" style={{ color: "var(--color-muted)" }}>unknown</span>
                      )}
                    </td>
                    <td className="px-3">
                      <span className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold tracking-[0.06em]" style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}>
                        {b.scheme.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-3 text-[12px]" style={{ color: "var(--color-body)" }}>
                      {b.card_type}
                    </td>
                    <td className="px-3 font-mono text-[12px] tabular-nums" style={{ color: "var(--color-body)" }}>
                      {b.country_code || "—"}
                    </td>
                    <td className="pr-4 text-right font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                      {timeAgo(b.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}
