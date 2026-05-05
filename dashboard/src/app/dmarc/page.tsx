"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ChevronLeft,
  Copy,
  Mail,
  Radar,
  ScrollText,
  ShieldAlert,
  Sparkles,
  Wand2,
} from "lucide-react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  api,
  type DmarcDnsCheckResponse,
  type DmarcForensicResponse,
  type DmarcMailboxConfigResponse,
  type DmarcPostureEntry,
  type DmarcRecordResponse,
  type DmarcReportResponse,
  type DmarcTrendPoint,
  type DmarcWizardResponse,
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
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { formatDate, timeAgo } from "@/lib/utils";
import { CoverageGate } from "@/components/shared/coverage-gate";

const POLICY_TONE: Record<string, StateTone> = {
  none: "muted",
  quarantine: "warning",
  reject: "error-strong",
};

const ALIGN_TONE: Record<string, StateTone> = {
  pass: "success",
  fail: "error-strong",
};

const inputStyle: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  outline: "none",
};

type DmarcTab = "reports" | "forensic" | "dns" | "mailbox";

export default function DmarcPage() {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [reports, setReports] = useState<DmarcReportResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [domainFilter, setDomainFilter] = useState("");
  const [selected, setSelected] = useState<DmarcReportResponse | null>(null);
  const [showWizard, setShowWizard] = useState(false);
  const [tab, setTab] = useState<DmarcTab>("reports");
  const [posture, setPosture] = useState<DmarcPostureEntry[]>([]);

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

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const data = await api.dmarc.listReports({
        organization_id: orgId,
        domain: domainFilter || undefined,
        limit: 200,
      });
      setReports(data);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load DMARC reports",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, domainFilter, toast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!orgId) return;
    let alive = true;
    (async () => {
      try {
        const p = await api.dmarc.posture(orgId);
        if (alive) setPosture(p);
      } catch {
        // posture is best-effort; do not toast
      }
    })();
    return () => {
      alive = false;
    };
  }, [orgId]);

  const domains = useMemo(() => {
    const s = new Set<string>();
    reports.forEach((r) => r.domain && s.add(r.domain));
    posture.forEach((p) => p.domain && s.add(p.domain));
    return Array.from(s).sort();
  }, [reports, posture]);

  return (
    <CoverageGate pageSlug="dmarc" pageLabel="DMARC">
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: ScrollText, label: "Governance" }}
        title="DMARC360"
        description="Aggregate-report ingest from your RUA mailbox plus a policy-progression wizard. Records are parsed XXE-safely and stored under the per-tenant retention policy."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
            <RefreshButton onClick={load} refreshing={loading} />
            <button
              onClick={() => setShowWizard(true)}
              className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold"
              style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
            >
              <Wand2 className="w-4 h-4" />
              Policy wizard
            </button>
          </>
        }
      />

      {selected ? (
        <ReportDetail
          report={selected}
          onBack={() => setSelected(null)}
          orgId={orgId}
        />
      ) : (
        <>
          <PostureStrip posture={posture} />
          <TabsBar tab={tab} setTab={setTab} />
          {tab === "dns" && (
            <DnsHealthPanel domains={domains} />
          )}
          {tab === "forensic" && (
            <ForensicPanel orgId={orgId} domainFilter={domainFilter} setDomainFilter={setDomainFilter} />
          )}
          {tab === "mailbox" && (
            <MailboxPanel orgId={orgId} />
          )}
          {tab === "reports" && (<>
          <div className="flex items-center gap-2">
            <input
              value={domainFilter}
              onChange={(e) => setDomainFilter(e.target.value)}
              placeholder="Filter by domain…"
              className="h-10 px-3 w-[260px] text-[12.5px] font-mono"
              style={inputStyle}
            />
          </div>
          <Section>
            {loading ? (
              <SkeletonRows rows={6} columns={6} />
            ) : reports.length === 0 ? (
              <Empty
                icon={ScrollText}
                title="No DMARC reports yet"
                description="Configure your domain's RUA endpoint to point at the configured mailbox; the parser ingests reports as they arrive. The report aggregate-report POST endpoint is also available for manual upload."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                      <Th align="left" className="pl-4">
                        Domain
                      </Th>
                      <Th align="left">Reporter</Th>
                      <Th align="left" className="w-[100px]">
                        Policy
                      </Th>
                      <Th align="left" className="w-[120px]">
                        Period
                      </Th>
                      <Th align="left" className="w-[100px]">
                        Volume
                      </Th>
                      <Th align="left">Pass / fail</Th>
                      <Th align="right" className="pr-4 w-[100px]">
                        Ingested
                      </Th>
                    </tr>
                  </thead>
                  <tbody>
                    {reports.map((r) => {
                      const passPct =
                        r.total_messages > 0
                          ? (r.pass_count / r.total_messages) * 100
                          : 0;
                      return (
                        <tr
                          key={r.id}
                          onClick={() => setSelected(r)}
                          className="h-12 cursor-pointer transition-colors"
                          style={{ borderBottom: "1px solid var(--color-border)" }}
                          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                          onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                        >
                          <td className="pl-4 font-mono text-[12.5px]" style={{ color: "var(--color-ink)" }}>
                            {r.domain}
                          </td>
                          <td className="px-3 text-[12.5px]" style={{ color: "var(--color-body)" }}>
                            {r.org_name || (
                              <span className="italic" style={{ color: "var(--color-muted)" }}>unknown</span>
                            )}
                          </td>
                          <td className="px-3">
                            {r.policy_p ? (
                              <StatePill
                                label={`p=${r.policy_p}`}
                                tone={POLICY_TONE[r.policy_p] || "neutral"}
                              />
                            ) : (
                              <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>—</span>
                            )}
                          </td>
                          <td className="px-3 font-mono text-[11px] tabular-nums whitespace-nowrap" style={{ color: "var(--color-body)" }}>
                            {formatDate(r.date_begin).split(",")[0]}
                          </td>
                          <td className="px-3 font-mono text-[12.5px] tabular-nums font-bold" style={{ color: "var(--color-ink)" }}>
                            {r.total_messages.toLocaleString()}
                          </td>
                          <td className="px-3">
                            <PassFailBar pct={passPct} pass={r.pass_count} fail={r.fail_count} />
                          </td>
                          <td className="pr-4 text-right font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                            {timeAgo(r.created_at)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Section>
          </>)}
        </>
      )}

      {showWizard && (
        <WizardModal onClose={() => setShowWizard(false)} />
      )}
    </div>
      </CoverageGate>
  );
}

// ─────────────────────────────────────────────────────────── Tabs

function TabsBar({ tab, setTab }: { tab: DmarcTab; setTab: (t: DmarcTab) => void }) {
  const items: Array<{ id: DmarcTab; label: string; icon: typeof Mail }> = [
    { id: "reports", label: "Aggregate reports", icon: ScrollText },
    { id: "forensic", label: "Forensic (RUF)", icon: ShieldAlert },
    { id: "dns", label: "DNS health", icon: Radar },
    { id: "mailbox", label: "Mailbox config", icon: Mail },
  ];
  return (
    <div className="flex items-center gap-1" style={{ borderBottom: "1px solid var(--color-border)" }}>
      {items.map((it) => {
        const active = it.id === tab;
        const Icon = it.icon;
        return (
          <button
            key={it.id}
            onClick={() => setTab(it.id)}
            className="inline-flex items-center gap-1.5 h-9 px-3 text-[12.5px] font-bold transition-colors"
            style={{
              borderBottom: active ? "2px solid var(--color-accent)" : "2px solid transparent",
              color: active ? "var(--color-ink)" : "var(--color-muted)",
              background: "transparent",
            }}
          >
            <Icon className="w-3.5 h-3.5" />
            {it.label}
          </button>
        );
      })}
    </div>
  );
}

function PostureStrip({ posture }: { posture: DmarcPostureEntry[] }) {
  if (!posture.length) return null;
  return (
    <div className="flex flex-wrap gap-3">
      {posture.slice(0, 6).map((p) => {
        const tone =
          p.score >= 80 ? "#007B55" : p.score >= 50 ? "#B76E00" : "#B71D18";
        return (
          <div
            key={p.domain}
            className="flex items-center gap-3 px-4 py-3 min-w-[220px]"
            style={{ borderRadius: 5, border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
          >
            <div className="text-[28px] font-extrabold tabular-nums leading-none" style={{ color: tone }}>
              {p.score}
            </div>
            <div className="space-y-0.5">
              <div className="font-mono text-[12px] font-bold" style={{ color: "var(--color-ink)" }}>{p.domain}</div>
              <div className="text-[10.5px]" style={{ color: "var(--color-muted)" }}>
                {String(p.components?.alignment_30d_pct ?? "0")}% pass · RUF {String(p.components?.ruf_count_30d ?? 0)}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────── DNS Health

function DnsHealthPanel({ domains }: { domains: string[] }) {
  const { toast } = useToast();
  const [domain, setDomain] = useState("");
  const [data, setData] = useState<DmarcDnsCheckResponse | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!domain && domains.length) setDomain(domains[0]);
  }, [domains, domain]);

  const run = async () => {
    if (!domain.trim()) return;
    setBusy(true);
    try {
      const r = await api.dmarc.dnsCheck(domain.trim());
      setData(r);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "DNS check failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          className="h-10 px-3 w-[300px] text-[13px] font-mono"
          style={{ borderRadius: 4, border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
        />
        <button
          onClick={run}
          disabled={busy || !domain.trim()}
          className="h-10 px-4 text-[13px] font-bold"
          style={{ borderRadius: 4, border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
        >
          {busy ? "Checking…" : "Check DNS"}
        </button>
      </div>

      {data && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <StatePill label={data.record_present ? "DMARC ✓" : "DMARC ✗"} tone={data.record_present ? "success" : "error-strong"} />
            <StatePill label={data.bimi_present ? "BIMI ✓" : "BIMI ✗"} tone={data.bimi_present ? "success" : "muted"} />
            <StatePill label={data.mta_sts_present ? "MTA-STS ✓" : "MTA-STS ✗"} tone={data.mta_sts_present ? "success" : "muted"} />
            <StatePill label={data.tls_rpt_present ? "TLS-RPT ✓" : "TLS-RPT ✗"} tone={data.tls_rpt_present ? "success" : "muted"} />
          </div>
          {data.raw_record && (
            <Section>
              <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>Raw record</h3>
              </div>
              <pre className="px-4 py-3 text-[12px] font-mono whitespace-pre-wrap break-all" style={{ color: "var(--color-ink)" }}>
                {data.raw_record}
              </pre>
            </Section>
          )}
          <Section>
            <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
              <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>Parsed tags</h3>
            </div>
            <div className="p-4 grid grid-cols-2 md:grid-cols-3 gap-2">
              {Object.entries(data.parsed_tags).map(([k, v]) => (
                <div key={k} className="flex items-center gap-2 text-[12.5px] font-mono">
                  <span style={{ color: "var(--color-muted)" }}>{k}=</span>
                  <span style={{ color: "var(--color-ink)" }}>{v}</span>
                </div>
              ))}
            </div>
          </Section>
          {data.warnings.length > 0 && (
            <Section>
              <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                <h3 className="text-[13px] font-bold" style={{ color: "#B71D18" }}>Warnings</h3>
              </div>
              <ul className="px-4 py-3 space-y-1 text-[12.5px]" style={{ color: "var(--color-body)" }}>
                {data.warnings.map((w, i) => <li key={i}>• {w}</li>)}
              </ul>
            </Section>
          )}
          {data.recommendations.length > 0 && (
            <Section>
              <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>Recommendations</h3>
              </div>
              <ul className="px-4 py-3 space-y-1 text-[12.5px]" style={{ color: "var(--color-body)" }}>
                {data.recommendations.map((r, i) => <li key={i}>• {r}</li>)}
              </ul>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────── Forensic

function ForensicPanel({
  orgId,
  domainFilter,
  setDomainFilter,
}: {
  orgId: string;
  domainFilter: string;
  setDomainFilter: (s: string) => void;
}) {
  const { toast } = useToast();
  const [rows, setRows] = useState<DmarcForensicResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<DmarcForensicResponse | null>(null);

  useEffect(() => {
    if (!orgId) return;
    let alive = true;
    (async () => {
      setLoading(true);
      try {
        const r = await api.dmarc.listForensic({ organization_id: orgId, domain: domainFilter || undefined, limit: 200 });
        if (alive) setRows(r);
      } catch (e) {
        toast("error", e instanceof Error ? e.message : "Failed to load forensic reports");
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, [orgId, domainFilter, toast]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <input
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value)}
          placeholder="Filter by domain…"
          className="h-10 px-3 w-[260px] text-[12.5px] font-mono"
          style={{ borderRadius: 4, border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)" }}
        />
      </div>
      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={5} />
        ) : rows.length === 0 ? (
          <Empty
            icon={ShieldAlert}
            title="No forensic reports yet"
            description="RUF reports land here when a configured mailbox receives them, or via direct upload (POST /dmarc/reports/forensic)."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4">Domain</Th>
                  <Th align="left">Source IP</Th>
                  <Th align="left">From</Th>
                  <Th align="left" className="w-[120px]">Auth</Th>
                  <Th align="right" className="pr-4 w-[120px]">Received</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => setSelected(r)}
                    className="h-12 cursor-pointer"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                  >
                    <td className="pl-4 font-mono text-[12.5px]" style={{ color: "var(--color-ink)" }}>{r.domain}</td>
                    <td className="px-3 font-mono text-[12px]" style={{ color: "var(--color-body)" }}>{r.source_ip || "—"}</td>
                    <td className="px-3 font-mono text-[11.5px]" style={{ color: "var(--color-body)" }}>{r.original_mail_from || "—"}</td>
                    <td className="px-3"><StatePill label={r.auth_failure || "?"} tone="error-strong" /></td>
                    <td className="pr-4 text-right font-mono text-[11px]" style={{ color: "var(--color-muted)" }}>{timeAgo(r.received_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      {selected && <ForensicDrawer row={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function ForensicDrawer({ row, onClose }: { row: DmarcForensicResponse; onClose: () => void }) {
  const lookalike = (row.agent_summary as any)?.lookalike;
  return (
    <ModalShell title={`Forensic — ${row.domain}`} onClose={onClose} width={760}>
      <div className="p-6 space-y-4 text-[12.5px]">
        <KV k="source_ip" v={row.source_ip} />
        <KV k="auth_failure" v={row.auth_failure} />
        <KV k="delivery_result" v={row.delivery_result} />
        <KV k="original_mail_from" v={row.original_mail_from} />
        <KV k="original_rcpt_to" v={row.original_rcpt_to} />
        <KV k="dkim_domain" v={row.dkim_domain} />
        <KV k="dkim_selector" v={row.dkim_selector} />
        <KV k="spf_domain" v={row.spf_domain} />
        {lookalike && (
          <Section>
            <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
              <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>Lookalike verdict</h3>
            </div>
            <div className="p-4 space-y-2 text-[12.5px]">
              <div><b>Severity:</b> {lookalike.severity}</div>
              <div><b>Matched:</b> {(lookalike.matched || []).join(", ") || "—"}</div>
              <div>{lookalike.rationale}</div>
              <button className="h-9 px-3 mt-2 text-[12.5px] font-bold" style={{ borderRadius: 4, border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}>
                Draft takedown
              </button>
            </div>
          </Section>
        )}
        {row.raw_headers && (
          <Section>
            <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
              <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>Original headers</h3>
            </div>
            <pre className="px-4 py-3 text-[11.5px] font-mono whitespace-pre-wrap break-all" style={{ color: "var(--color-ink)" }}>{row.raw_headers}</pre>
          </Section>
        )}
      </div>
    </ModalShell>
  );
}

function KV({ k, v }: { k: string; v: string | null | undefined }) {
  return (
    <div className="flex items-baseline gap-3">
      <span className="font-mono text-[11px] uppercase tracking-[0.08em] w-[160px]" style={{ color: "var(--color-muted)" }}>{k}</span>
      <span className="font-mono text-[12.5px]" style={{ color: "var(--color-ink)" }}>{v || "—"}</span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────── Mailbox config

function MailboxPanel({ orgId }: { orgId: string }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<DmarcMailboxConfigResponse[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ host: "", port: 993, username: "", password: "", folder: "INBOX", enabled: true });
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const r = await api.dmarc.listMailboxConfigs(orgId);
      setRows(r);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to load mailbox configs (admin only?)");
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => { reload(); }, [reload]);

  const save = async () => {
    if (!form.host || !form.username || !form.password) {
      toast("error", "host, username, password required");
      return;
    }
    setBusy(true);
    try {
      await api.dmarc.upsertMailboxConfig({ organization_id: orgId, ...form });
      toast("success", "Mailbox config saved (password encrypted at rest)");
      setShowForm(false);
      setForm({ host: "", port: 993, username: "", password: "", folder: "INBOX", enabled: true });
      reload();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Save failed");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string) => {
    try {
      await api.dmarc.deleteMailboxConfig(id);
      toast("success", "Deleted");
      reload();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Delete failed");
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-[12.5px]" style={{ color: "var(--color-muted)" }}>
          IMAP mailbox the worker polls hourly for RUA/RUF attachments. Password is Fernet-encrypted server-side.
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="h-10 px-4 text-[13px] font-bold"
          style={{ borderRadius: 4, border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
        >
          + Add mailbox
        </button>
      </div>
      <Section>
        {loading ? (
          <SkeletonRows rows={3} columns={5} />
        ) : rows.length === 0 ? (
          <Empty icon={Mail} title="No mailbox configured" description="Add an IMAPS endpoint and the worker will start draining DMARC reports on its next tick." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4">Host</Th>
                  <Th align="left">Username</Th>
                  <Th align="left">Folder</Th>
                  <Th align="left">Status</Th>
                  <Th align="right" className="pr-4">Actions</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className="h-12" style={{ borderBottom: "1px solid var(--color-border)" }}>
                    <td className="pl-4 font-mono text-[12.5px]">{r.host}:{r.port}</td>
                    <td className="px-3 font-mono text-[12px]">{r.username}</td>
                    <td className="px-3 font-mono text-[12px]">{r.folder}</td>
                    <td className="px-3">
                      {r.last_error ? <StatePill label={`error: ${r.last_error.slice(0, 40)}`} tone="error-strong" /> : <StatePill label={r.enabled ? "enabled" : "paused"} tone={r.enabled ? "success" : "muted"} />}
                    </td>
                    <td className="pr-4 text-right">
                      <button onClick={() => remove(r.id)} className="text-[12px] font-bold" style={{ color: "#B71D18" }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
      {showForm && (
        <ModalShell title="Configure IMAP mailbox" onClose={() => setShowForm(false)} width={520}>
          <div className="p-6 space-y-4">
            <Field label="IMAP host" required><input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} className="w-full h-10 px-3 text-[13px] font-mono" style={inputStyle} placeholder="imap.gmail.com" /></Field>
            <Field label="Port"><input value={form.port} type="number" onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 993 })} className="w-full h-10 px-3 text-[13px] font-mono" style={inputStyle} /></Field>
            <Field label="Username" required><input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} className="w-full h-10 px-3 text-[13px] font-mono" style={inputStyle} /></Field>
            <Field label="Password" required hint="Encrypted server-side via Fernet."><input value={form.password} type="password" onChange={(e) => setForm({ ...form, password: e.target.value })} className="w-full h-10 px-3 text-[13px] font-mono" style={inputStyle} /></Field>
            <Field label="Folder"><input value={form.folder} onChange={(e) => setForm({ ...form, folder: e.target.value })} className="w-full h-10 px-3 text-[13px] font-mono" style={inputStyle} /></Field>
          </div>
          <ModalFooter onCancel={() => setShowForm(false)} onSubmit={save} submitLabel={busy ? "Saving…" : "Save"} disabled={busy} />
        </ModalShell>
      )}
    </div>
  );
}

function PassFailBar({
  pct,
  pass,
  fail,
}: {
  pct: number;
  pass: number;
  fail: number;
}) {
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,86,48,0.3)" }}>
        <div
          className="h-full transition-all"
          style={{ width: `${pct}%`, background: "#007B55" }}
        />
      </div>
      <span className="font-mono text-[11px] tabular-nums" style={{ color: "#007B55" }}>
        {pass.toLocaleString()}
      </span>
      <span style={{ color: "var(--color-border)" }}>/</span>
      <span className="font-mono text-[11px] tabular-nums" style={{ color: "#B71D18" }}>
        {fail.toLocaleString()}
      </span>
    </div>
  );
}

function ReportDetail({
  report,
  onBack,
  orgId,
}: {
  report: DmarcReportResponse;
  onBack: () => void;
  orgId: string;
}) {
  const { toast } = useToast();
  const [records, setRecords] = useState<DmarcRecordResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [trend, setTrend] = useState<DmarcTrendPoint[]>([]);
  const [planning, setPlanning] = useState(false);
  const [planMd, setPlanMd] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        setRecords(await api.dmarc.listRecords(report.id));
      } catch (e) {
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load records",
        );
      } finally {
        setLoading(false);
      }
      try {
        const t = await api.dmarc.trends(report.domain, { organization_id: orgId, days: 30 });
        setTrend(t);
      } catch {
        // optional
      }
    })();
  }, [report.id, report.domain, orgId, toast]);

  const runPlan = async () => {
    setPlanning(true);
    try {
      const r = await api.dmarc.planRollout({ organization_id: orgId, domain: report.domain });
      if (r.markdown) {
        setPlanMd(r.markdown);
      } else {
        toast("info", `Rollout plan queued (task ${r.task_id.slice(0, 8)} status=${r.status}). Refresh in a few seconds.`);
      }
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Plan-rollout failed");
    } finally {
      setPlanning(false);
    }
  };

  const rcaEntries = report.rca ? Object.entries(report.rca) : [];

  return (
    <div className="space-y-5">
      <button
        onClick={onBack}
        className="inline-flex items-center gap-1.5 text-[12px] font-semibold transition-colors"
        style={{ color: "var(--color-muted)" }}
        onMouseEnter={e => (e.currentTarget.style.color = "var(--color-ink)")}
        onMouseLeave={e => (e.currentTarget.style.color = "var(--color-muted)")}
      >
        <ChevronLeft className="w-3.5 h-3.5" />
        All reports
      </button>

      <div className="flex items-center gap-3">
        {report.policy_p ? (
          <StatePill
            label={`p=${report.policy_p}`}
            tone={POLICY_TONE[report.policy_p] || "neutral"}
          />
        ) : null}
        <h1 className="text-[24px] font-extrabold leading-tight tracking-[-0.01em] font-mono" style={{ color: "var(--color-ink)" }}>
          {report.domain}
        </h1>
        <span className="font-mono text-[11px] tabular-nums" style={{ color: "var(--color-muted)" }}>
          report {report.report_id}
        </span>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={runPlan}
          disabled={planning}
          className="inline-flex items-center gap-2 h-9 px-3 text-[12.5px] font-bold"
          style={{ borderRadius: 4, border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
        >
          <Sparkles className="w-3.5 h-3.5" />
          {planning ? "Generating…" : "Plan rollout (Bridge)"}
        </button>
      </div>

      <div style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}>
        <div className="grid grid-cols-2 md:grid-cols-5">
          <Stat label="Total" value={report.total_messages} />
          <Stat label="Pass" value={report.pass_count} tone="success" />
          <Stat label="Fail" value={report.fail_count} tone="error" />
          <Stat label="Quarantined" value={report.quarantine_count} tone="warning" />
          <Stat label="Rejected" value={report.reject_count} tone="error" />
        </div>
      </div>

      {trend.length > 1 && (
        <Section>
          <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>30-day pass-%</h3>
          </div>
          <div style={{ height: 220 }} className="px-4 py-3">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trend} margin={{ top: 8, right: 16, bottom: 8, left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                <XAxis dataKey="day" stroke="var(--color-muted)" fontSize={11} />
                <YAxis domain={[0, 100]} stroke="var(--color-muted)" fontSize={11} />
                <Tooltip />
                <Line type="monotone" dataKey="pass_pct" stroke="#007B55" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Section>
      )}

      {rcaEntries.length > 0 && (
        <Section>
          <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>Bridge RCA</h3>
            <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
              LLM-classified root causes for misaligned source IPs.
            </p>
          </div>
          <div className="p-4 space-y-3">
            {rcaEntries.map(([ip, entry]: [string, any]) => (
              <div key={ip} className="text-[12.5px]">
                <div className="font-mono font-bold" style={{ color: "var(--color-ink)" }}>{ip} <span style={{ color: "var(--color-muted)" }}>· {entry.cause}</span></div>
                <div style={{ color: "var(--color-body)" }}>{entry.recommendation}</div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {planMd && (
        <ModalShell title={`Rollout plan — ${report.domain}`} onClose={() => setPlanMd(null)} width={760}>
          <div className="p-6 text-[13px] whitespace-pre-wrap font-mono" style={{ color: "var(--color-ink)" }}>{planMd}</div>
        </ModalShell>
      )}

      <Section>
        <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
          <h3 className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
            Per-IP records
          </h3>
          <p className="text-[11.5px] mt-0.5" style={{ color: "var(--color-muted)" }}>
            Source IPs as reported by the receiver. Alignment columns
            indicate whether SPF / DKIM checks aligned with the From header.
          </p>
        </div>
        {loading ? (
          <SkeletonRows rows={6} columns={6} />
        ) : records.length === 0 ? (
          <div className="px-6 py-8 text-center">
            <p className="text-[12.5px]" style={{ color: "var(--color-muted)" }}>
              No per-record data — the report only carried summary counts.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4">
                    Source IP
                  </Th>
                  <Th align="left" className="w-[80px]">
                    Count
                  </Th>
                  <Th align="left" className="w-[110px]">
                    Disposition
                  </Th>
                  <Th align="left" className="w-[110px]">
                    SPF
                  </Th>
                  <Th align="left" className="w-[110px]">
                    DKIM
                  </Th>
                  <Th align="left">Header from</Th>
                </tr>
              </thead>
              <tbody>
                {records.map((rec) => (
                  <tr
                    key={rec.id}
                    className="h-11 transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  >
                    <td className="pl-4 font-mono text-[12px] tabular-nums" style={{ color: "var(--color-ink)" }}>
                      {rec.source_ip}
                    </td>
                    <td className="px-3 font-mono text-[12.5px] tabular-nums" style={{ color: "var(--color-body)" }}>
                      {rec.count}
                    </td>
                    <td className="px-3">
                      {rec.disposition ? (
                        <StatePill
                          label={rec.disposition}
                          tone={POLICY_TONE[rec.disposition] || "neutral"}
                        />
                      ) : (
                        <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>—</span>
                      )}
                    </td>
                    <td className="px-3">
                      <AlignCell
                        result={rec.spf_result}
                        aligned={rec.spf_aligned}
                      />
                    </td>
                    <td className="px-3">
                      <AlignCell
                        result={rec.dkim_result}
                        aligned={rec.dkim_aligned}
                      />
                    </td>
                    <td className="px-3 font-mono text-[12px]" style={{ color: "var(--color-body)" }}>
                      {rec.header_from || (
                        <span className="italic" style={{ color: "var(--color-muted)" }}>—</span>
                      )}
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

function AlignCell({
  result,
  aligned,
}: {
  result: string | null;
  aligned: boolean | null;
}) {
  if (!result) return <span className="text-[11px]" style={{ color: "var(--color-muted)" }}>—</span>;
  return (
    <div className="flex items-center gap-1.5">
      <StatePill
        label={result}
        tone={ALIGN_TONE[result] || "neutral"}
      />
      {aligned !== null ? (
        <span
          className="text-[10.5px] font-bold tracking-[0.06em]"
          style={{ color: aligned ? "#007B55" : "#B71D18" }}
        >
          {aligned ? "ALIGN" : "MISALIGN"}
        </span>
      ) : null}
    </div>
  );
}

function Stat({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: number;
  tone?: "neutral" | "success" | "error" | "warning";
}) {
  const valueColor =
    tone === "success"
      ? "#007B55"
      : tone === "error"
      ? "#FF5630"
      : tone === "warning"
      ? "#B76E00"
      : "var(--color-ink)";
  return (
    <div className="px-4 py-4" style={{ borderRight: "1px solid var(--color-border)" }}>
      <div className="text-[10px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
        {label}
      </div>
      <div
        className="mt-1.5 font-mono tabular-nums text-[24px] leading-none font-extrabold tracking-[-0.01em]"
        style={{ color: valueColor }}
      >
        {value.toLocaleString()}
      </div>
    </div>
  );
}

function WizardModal({ onClose }: { onClose: () => void }) {
  const { toast } = useToast();
  const [domain, setDomain] = useState("");
  const [includes, setIncludes] = useState("");
  const [selectors, setSelectors] = useState("");
  const [rua, setRua] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<DmarcWizardResponse | null>(null);

  const run = async () => {
    if (!domain.trim() || busy) return;
    setBusy(true);
    try {
      const r = await api.dmarc.runWizard(domain.trim(), {
        sending_includes: includes
          .split(/[\n,\s]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        dkim_selectors: selectors
          .split(/[\n,\s]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        rua_endpoint: rua.trim() || undefined,
      });
      setResult(r);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Wizard failed");
    } finally {
      setBusy(false);
    }
  };

  const copy = async (txt: string) => {
    try {
      await navigator.clipboard.writeText(txt);
      toast("success", "Copied to clipboard");
    } catch {
      toast("error", "Copy failed");
    }
  };

  return (
    <ModalShell title="DMARC policy wizard" onClose={onClose} width={680}>
      {!result ? (
        <>
          <div className="p-6 space-y-5">
            <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
              Generates a recommended SPF + DKIM + DMARC progression to roll
              from <code className="font-mono">p=none</code> →{" "}
              <code className="font-mono">p=quarantine</code> →{" "}
              <code className="font-mono">p=reject</code> with sane RUA
              reporting. Output is read-only — apply the records manually
              once verified.
            </p>
            <Field label="Domain" required>
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="w-full h-10 px-3 text-[13px] font-mono"
                style={inputStyle}
                placeholder="argusbank.demo"
                autoFocus
              />
            </Field>
            <Field
              label="Sending includes"
              hint="Mail providers / SPF includes (one per line)."
            >
              <textarea
                value={includes}
                onChange={(e) => setIncludes(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 text-[13px] font-mono resize-none"
                style={inputStyle}
                placeholder="_spf.google.com&#10;mail.zendesk.com"
              />
            </Field>
            <Field
              label="DKIM selectors"
              hint="Provider DKIM selectors (one per line)."
            >
              <textarea
                value={selectors}
                onChange={(e) => setSelectors(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 text-[13px] font-mono resize-none"
                style={inputStyle}
                placeholder="google._domainkey&#10;zendesk1._domainkey"
              />
            </Field>
            <Field label="RUA endpoint" hint="Where receivers report.">
              <input
                value={rua}
                onChange={(e) => setRua(e.target.value)}
                className="w-full h-10 px-3 text-[13px] font-mono"
                style={inputStyle}
                placeholder="mailto:dmarc@argusbank.demo"
              />
            </Field>
          </div>
          <ModalFooter
            onCancel={onClose}
            onSubmit={run}
            submitLabel={busy ? "Generating…" : "Generate"}
            disabled={busy || !domain.trim()}
          />
        </>
      ) : (
        <div className="p-6 space-y-5">
          <p className="text-[13px]" style={{ color: "var(--color-body)" }}>{result.rationale}</p>
          <RecordRow label="SPF" value={result.spf_record} onCopy={copy} />
          {result.dkim_records.map((d, i) => (
            <RecordRow
              key={`dkim-${i}`}
              label={`DKIM (${d.selector || "?"})`}
              value={d.record || ""}
              onCopy={copy}
            />
          ))}
          <div>
            <div className="text-[10.5px] font-bold uppercase tracking-[0.12em] mb-2" style={{ color: "var(--color-muted)" }}>
              DMARC progression
            </div>
            <div className="space-y-2">
              {result.dmarc_records_progression.map((d, i) => (
                <RecordRow
                  key={`dmarc-${i}`}
                  label={`stage ${i + 1} (p=${d.policy})`}
                  value={d.record || ""}
                  onCopy={copy}
                />
              ))}
            </div>
          </div>
          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              onClick={onClose}
              className="h-9 px-3 text-[13px] font-bold transition-colors"
              style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
              onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
              onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
            >
              Close
            </button>
            <button
              onClick={() => {
                setResult(null);
                setDomain("");
                setIncludes("");
                setSelectors("");
                setRua("");
              }}
              className="h-9 px-3 text-[13px] font-bold"
              style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
            >
              Run again
            </button>
          </div>
        </div>
      )}
    </ModalShell>
  );
}

function RecordRow({
  label,
  value,
  onCopy,
}: {
  label: string;
  value: string;
  onCopy: (s: string) => void;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10.5px] font-bold uppercase tracking-[0.12em]" style={{ color: "var(--color-muted)" }}>
          {label}
        </span>
        <button
          onClick={() => onCopy(value)}
          className="inline-flex items-center gap-1 h-6 px-2 text-[10.5px] font-bold transition-colors"
          style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }}
          onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface-muted)")}
          onMouseLeave={e => (e.currentTarget.style.background = "var(--color-canvas)")}
        >
          <Copy className="w-3 h-3" />
          COPY
        </button>
      </div>
      <pre className="px-3 py-2 text-[12px] font-mono overflow-x-auto whitespace-pre-wrap break-all" style={{ borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-surface)", color: "var(--color-ink)" }}>
        {value || <span className="italic" style={{ color: "var(--color-muted)" }}>(empty)</span>}
      </pre>
    </div>
  );
}
