"use client";

import { useCallback, useEffect, useState } from "react";
import {
  ChevronLeft,
  Copy,
  ScrollText,
  Wand2,
} from "lucide-react";
import {
  api,
  type DmarcRecordResponse,
  type DmarcReportResponse,
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

export default function DmarcPage() {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [reports, setReports] = useState<DmarcReportResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [domainFilter, setDomainFilter] = useState("");
  const [selected, setSelected] = useState<DmarcReportResponse | null>(null);
  const [showWizard, setShowWizard] = useState(false);

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

  return (
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
        />
      ) : (
        <>
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
        </>
      )}

      {showWizard && (
        <WizardModal onClose={() => setShowWizard(false)} />
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
}: {
  report: DmarcReportResponse;
  onBack: () => void;
}) {
  const { toast } = useToast();
  const [records, setRecords] = useState<DmarcRecordResponse[]>([]);
  const [loading, setLoading] = useState(true);

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
    })();
  }, [report.id, toast]);

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

      <div style={{ borderRadius: "5px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }}>
        <div className="grid grid-cols-2 md:grid-cols-5">
          <Stat label="Total" value={report.total_messages} />
          <Stat label="Pass" value={report.pass_count} tone="success" />
          <Stat label="Fail" value={report.fail_count} tone="error" />
          <Stat label="Quarantined" value={report.quarantine_count} tone="warning" />
          <Stat label="Rejected" value={report.reject_count} tone="error" />
        </div>
      </div>

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
