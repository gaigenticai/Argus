"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Megaphone,
  Plus,
  Send,
  XCircle,
  ChevronLeft,
} from "lucide-react";
import {
  api,
  type AdvisoryResponse,
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
import { formatDate, timeAgo } from "@/lib/utils";
import { CoverageGate } from "@/components/shared/coverage-gate";

const STATE_TONE: Record<string, StateTone> = {
  draft: "muted",
  published: "info",
  revoked: "error-strong",
};

const SEVERITY_TONE: Record<string, StateTone> = {
  critical: "error-strong",
  high: "error",
  medium: "warning",
  low: "info",
  info: "muted",
};

const inputStyle: React.CSSProperties = {
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  outline: "none",
};

export default function AdvisoriesPage() {
  const { toast } = useToast();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgIdState] = useState("");
  const [rows, setRows] = useState<AdvisoryResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<AdvisoryResponse | null>(null);
  const [stateFilter, setStateFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [kevOnly, setKevOnly] = useState(false);

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
    setLoading(true);
    try {
      const data = await api.news.listAdvisories({
        organization_id: orgId || undefined,
        state: stateFilter === "all" ? undefined : stateFilter,
        severity: severityFilter === "all" ? undefined : severityFilter,
        limit: 500,
      });
      setRows(kevOnly ? data.filter((a) => a.is_kev) : data);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load advisories",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, stateFilter, severityFilter, kevOnly, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const publish = async (a: AdvisoryResponse) => {
    try {
      await api.news.publishAdvisory(a.id);
      toast("success", `Published "${a.title}"`);
      await load();
      if (selected?.id === a.id) {
        setSelected({ ...a, state: "published", published_at: new Date().toISOString() });
      }
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Publish failed");
    }
  };

  const revoke = async (a: AdvisoryResponse, reason: string) => {
    try {
      await api.news.revokeAdvisory(a.id, reason);
      toast("success", "Advisory revoked");
      await load();
      setSelected(null);
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Revoke failed");
    }
  };

  return (
    <CoverageGate pageSlug="advisories" pageLabel="Advisories">
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Megaphone, label: "Intelligence" }}
        title="Advisories"
        description="Internal SOC advisories — phishing waves, vendor breaches, urgent CVE escalations. Drafts go through a publish step before notification fan-out, and revocation requires a documented reason."
        actions={
          <>
            <OrgSwitcher orgs={orgs} orgId={orgId} onChange={setOrgId} />
            <RefreshButton onClick={load} refreshing={loading} />
            <button
              onClick={async () => {
                try {
                  const r = await api.news.ingestCisaKev();
                  toast(
                    "success",
                    `CISA KEV — inserted ${r.inserted}, updated ${r.updated}, total ${r.total}`,
                  );
                  await load();
                } catch (e) {
                  toast("error", e instanceof Error ? e.message : "CISA KEV ingest failed");
                }
              }}
              className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold"
              style={{
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
            >
              Ingest CISA KEV
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold"
              style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
            >
              <Plus className="w-4 h-4" />
              New advisory
            </button>
          </>
        }
      />

      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="State"
          value={stateFilter}
          options={[
            { value: "all", label: "Any state" },
            { value: "draft", label: "Draft" },
            { value: "published", label: "Published" },
            { value: "revoked", label: "Revoked" },
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
            { value: "info", label: "Info" },
          ]}
          onChange={setSeverityFilter}
        />
        <label className="inline-flex items-center gap-2 text-[12px] font-semibold ml-2" style={{ color: "var(--color-muted)" }}>
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={(e) => setKevOnly(e.target.checked)}
          />
          KEV only
        </label>
      </div>

      {selected ? (
        <AdvisoryDetail
          advisory={selected}
          onBack={() => setSelected(null)}
          onPublish={() => publish(selected)}
          onRevoke={(reason) => revoke(selected, reason)}
        />
      ) : (
        <Section>
          {loading ? (
            <SkeletonRows rows={6} columns={5} />
          ) : rows.length === 0 ? (
            <Empty
              icon={Megaphone}
              title="No advisories"
              description="Draft a new SOC advisory to share situational awareness with the org. Publishing fans out via the notification dispatcher."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                    <Th align="left" className="pl-4 w-[100px]">
                      Severity
                    </Th>
                    <Th align="left">Advisory</Th>
                    <Th align="left">CVEs / tags</Th>
                    <Th align="left" className="w-[110px]">
                      State
                    </Th>
                    <Th align="right" className="pr-4 w-[120px]">
                      Updated
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((a) => (
                    <tr
                      key={a.id}
                      onClick={() => setSelected(a)}
                      className="h-14 cursor-pointer transition-colors"
                      style={{ borderBottom: "1px solid var(--color-border)" }}
                      onMouseEnter={e => (e.currentTarget.style.background = "var(--color-surface)")}
                      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                    >
                      <td className="pl-4">
                        <StatePill
                          label={a.severity}
                          tone={SEVERITY_TONE[a.severity] || "neutral"}
                        />
                      </td>
                      <td className="px-3">
                        <div className="text-[13.5px] font-semibold line-clamp-1" style={{ color: "var(--color-ink)" }}>
                          {a.title}
                        </div>
                        <div className="text-[11px] font-mono tabular-nums mt-0.5" style={{ color: "var(--color-muted)" }}>
                          {a.slug}
                        </div>
                      </td>
                      <td className="px-3">
                        <div className="flex flex-wrap items-center gap-1">
                          {a.is_kev && (
                            <span
                              className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold uppercase tracking-wide"
                              style={{ borderRadius: "4px", background: "#B71D18", color: "#fff" }}
                            >
                              KEV
                            </span>
                          )}
                          {typeof a.cvss3_score === "number" && (
                            <span
                              className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold"
                              style={{ borderRadius: "4px", background: "rgba(183,29,24,0.10)", color: "#B71D18" }}
                            >
                              CVSS {a.cvss3_score.toFixed(1)}
                            </span>
                          )}
                          {typeof a.epss_score === "number" && (
                            <span
                              className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-bold"
                              style={{ borderRadius: "4px", background: "rgba(255,171,0,0.12)", color: "#B76E00" }}
                            >
                              EPSS {(a.epss_score * 100).toFixed(0)}%
                            </span>
                          )}
                          {a.cve_ids.slice(0, 2).map((c) => (
                            <span
                              key={c}
                              className="inline-flex items-center h-[18px] px-1.5 text-[10.5px] font-mono tabular-nums tracking-wide"
                              style={{ borderRadius: "4px", border: "1px solid rgba(255,86,48,0.3)", background: "rgba(255,86,48,0.05)", color: "#B71D18" }}
                            >
                              {c}
                            </span>
                          ))}
                          {a.source && a.source !== "manual" && (
                            <span
                              className="inline-flex items-center h-[16px] px-1 text-[10px] font-bold uppercase"
                              style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                            >
                              {a.source}
                            </span>
                          )}
                          {a.tags.slice(0, 2).map((t) => (
                            <span
                              key={t}
                              className="inline-flex items-center h-[16px] px-1 text-[10px] font-bold"
                              style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                        {a.triage_state && a.triage_state !== "new" && (
                          <div className="text-[10px] mt-1" style={{ color: "var(--color-muted)" }}>
                            triage: <span className="font-semibold">{a.triage_state}</span>
                          </div>
                        )}
                      </td>
                      <td className="px-3">
                        <StatePill
                          label={a.state}
                          tone={STATE_TONE[a.state] || "neutral"}
                        />
                      </td>
                      <td className="pr-4 text-right font-mono text-[11.5px] tabular-nums" style={{ color: "var(--color-muted)" }}>
                        {timeAgo(a.updated_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      )}

      {showCreate && (
        <CreateAdvisoryModal
          orgId={orgId || null}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            load();
          }}
        />
      )}
    </div>
      </CoverageGate>
  );
}

function AdvisoryDetail({
  advisory,
  onBack,
  onPublish,
  onRevoke,
}: {
  advisory: AdvisoryResponse;
  onBack: () => void;
  onPublish: () => void;
  onRevoke: (reason: string) => void;
}) {
  const [showRevoke, setShowRevoke] = useState(false);
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
        All advisories
      </button>
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <StatePill
              label={advisory.severity}
              tone={SEVERITY_TONE[advisory.severity] || "neutral"}
            />
            <StatePill
              label={advisory.state}
              tone={STATE_TONE[advisory.state] || "neutral"}
            />
            <span className="font-mono text-[11px] tabular-nums" style={{ color: "var(--color-muted)" }}>
              {advisory.slug}
            </span>
          </div>
          <h1 className="text-[24px] font-extrabold leading-tight tracking-[-0.01em]" style={{ color: "var(--color-ink)" }}>
            {advisory.title}
          </h1>
        </div>
        <div className="flex items-center gap-2">
          {advisory.state === "draft" ? (
            <button
              onClick={onPublish}
              className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold"
              style={{ borderRadius: "4px", border: "1px solid rgba(0,167,111,0.5)", background: "rgba(0,167,111,0.1)", color: "#007B55" }}
            >
              <Send className="w-3.5 h-3.5" />
              Publish
            </button>
          ) : null}
          {advisory.state === "published" ? (
            <button
              onClick={() => setShowRevoke(true)}
              className="inline-flex items-center gap-2 h-9 px-3 text-[13px] font-bold"
              style={{ borderRadius: "4px", border: "1px solid rgba(255,86,48,0.4)", background: "transparent", color: "#B71D18" }}
            >
              <XCircle className="w-3.5 h-3.5" />
              Revoke
            </button>
          ) : null}
        </div>
      </div>
      <TriageBar advisory={advisory} />
      <AffectedExposuresPanel advisoryId={advisory.id} />
      <CommentsPanel advisoryId={advisory.id} />
      <Section>
        <div className="px-6 py-5">
          <article className="prose prose-sm max-w-none whitespace-pre-wrap text-[13.5px] leading-relaxed" style={{ color: "var(--color-body)" }}>
            {advisory.body_markdown}
          </article>
        </div>
      </Section>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Section>
          <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[12px] font-bold uppercase tracking-[0.1em]" style={{ color: "var(--color-body)" }}>
              CVE references
            </h3>
          </div>
          <div className="px-4 py-3">
            {advisory.cve_ids.length === 0 ? (
              <p className="text-[12.5px] italic" style={{ color: "var(--color-muted)" }}>none</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {advisory.cve_ids.map((c) => (
                  <a
                    key={c}
                    href={`https://nvd.nist.gov/vuln/detail/${c}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center h-[20px] px-1.5 text-[10.5px] font-mono tabular-nums tracking-wide transition-colors"
                    style={{ borderRadius: "4px", border: "1px solid rgba(255,86,48,0.3)", background: "rgba(255,86,48,0.05)", color: "#B71D18" }}
                    onMouseEnter={e => (e.currentTarget.style.borderColor = "rgba(255,86,48,0.6)")}
                    onMouseLeave={e => (e.currentTarget.style.borderColor = "rgba(255,86,48,0.3)")}
                  >
                    {c}
                  </a>
                ))}
              </div>
            )}
          </div>
        </Section>

        <Section>
          <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[12px] font-bold uppercase tracking-[0.1em]" style={{ color: "var(--color-body)" }}>
              External references
            </h3>
          </div>
          <div className="px-4 py-3">
            {advisory.references.length === 0 ? (
              <p className="text-[12.5px] italic" style={{ color: "var(--color-muted)" }}>none</p>
            ) : (
              <ul className="space-y-1">
                {advisory.references.map((u, i) => (
                  <li key={`${u}-${i}`}>
                    <a
                      href={u}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[12px] break-all transition-colors"
                      style={{ color: "var(--color-accent)" }}
                      onMouseEnter={e => (e.currentTarget.style.opacity = "0.8")}
                      onMouseLeave={e => (e.currentTarget.style.opacity = "1")}
                    >
                      {u}
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Section>
      </div>

      <div className="text-[11px] font-mono tabular-nums flex items-center gap-3" style={{ color: "var(--color-muted)" }}>
        <span>created {timeAgo(advisory.created_at)}</span>
        {advisory.published_at ? (
          <>
            <span style={{ color: "var(--color-border)" }}>·</span>
            <span>published {formatDate(advisory.published_at)}</span>
          </>
        ) : null}
        {advisory.revoked_at ? (
          <>
            <span style={{ color: "var(--color-border)" }}>·</span>
            <span style={{ color: "#B71D18" }}>
              revoked {formatDate(advisory.revoked_at)} —{" "}
              {advisory.revoked_reason}
            </span>
          </>
        ) : null}
      </div>

      {showRevoke && (
        <RevokeModal
          onClose={() => setShowRevoke(false)}
          onSubmit={(reason) => {
            onRevoke(reason);
            setShowRevoke(false);
          }}
        />
      )}
    </div>
  );
}

function CreateAdvisoryModal({
  orgId,
  onClose,
  onCreated,
}: {
  orgId: string | null;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const [title, setTitle] = useState("");
  const [slug, setSlug] = useState("");
  const [severity, setSeverity] = useState("high");
  const [body, setBody] = useState("");
  const [cves, setCves] = useState("");
  const [tags, setTags] = useState("");
  const [refs, setRefs] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!title.trim() || !slug.trim() || !body.trim() || busy) return;
    setBusy(true);
    try {
      await api.news.createAdvisory({
        organization_id: orgId || undefined,
        slug: slug.trim().toLowerCase(),
        title: title.trim(),
        body_markdown: body,
        severity,
        cve_ids: cves
          .split(/[\n,\s]+/)
          .map((s) => s.trim().toUpperCase())
          .filter(Boolean),
        tags: tags
          .split(/[\n,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        references: refs
          .split(/[\n,\s]+/)
          .map((s) => s.trim())
          .filter(Boolean),
      });
      toast("success", "Advisory drafted");
      onCreated();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Create failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Draft advisory" onClose={onClose} width={680}>
      <div className="p-6 space-y-5">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Title" required>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full h-10 px-3 text-[13px]"
              style={inputStyle}
              placeholder="Mass phishing wave targeting argusbank.demo"
              autoFocus
            />
          </Field>
          <Field label="Slug" required hint="kebab-case identifier.">
            <input
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              className="w-full h-10 px-3 text-[13px] font-mono"
              style={inputStyle}
              placeholder="phishing-wave-2026-04"
            />
          </Field>
        </div>
        <Field label="Severity" required>
          <div className="grid grid-cols-5 gap-1.5">
            {["critical", "high", "medium", "low", "info"].map((s) => {
              const active = severity === s;
              return (
                <button
                  key={s}
                  onClick={() => setSeverity(s)}
                  className="h-10 flex items-center justify-center transition-all"
                  style={active
                    ? { borderRadius: "4px", border: "1px solid var(--color-ink)", background: "var(--color-canvas)", boxShadow: "0 0 0 2px rgba(32,21,21,0.08)" }
                    : { borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)" }
                  }
                >
                  <StatePill
                    label={s}
                    tone={SEVERITY_TONE[s] || "neutral"}
                  />
                </button>
              );
            })}
          </div>
        </Field>
        <Field
          label="Body"
          required
          hint="Markdown. Newlines and bullets render verbatim in the detail view."
        >
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            rows={8}
            className="w-full px-3 py-2 text-[13px] font-mono resize-none"
            style={inputStyle}
            placeholder="What happened, who's affected, what to do."
          />
        </Field>
        <Field label="CVE IDs" hint="Comma or newline separated.">
          <input
            value={cves}
            onChange={(e) => setCves(e.target.value)}
            className="w-full h-10 px-3 text-[13px] font-mono"
            style={inputStyle}
            placeholder="CVE-2026-1234, CVE-2026-5678"
          />
        </Field>
        <Field label="Tags">
          <input
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            className="w-full h-10 px-3 text-[13px]"
            style={inputStyle}
            placeholder="phishing, kyc, urgent"
          />
        </Field>
        <Field label="References">
          <textarea
            value={refs}
            onChange={(e) => setRefs(e.target.value)}
            rows={2}
            className="w-full px-3 py-2 text-[13px] font-mono resize-none"
            style={inputStyle}
            placeholder="https://msrc.microsoft.com/…&#10;https://www.cisa.gov/…"
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Saving…" : "Save draft"}
        disabled={
          busy || !title.trim() || !slug.trim() || !body.trim()
        }
      />
    </ModalShell>
  );
}

function RevokeModal({
  onClose,
  onSubmit,
}: {
  onClose: () => void;
  onSubmit: (reason: string) => void;
}) {
  const [reason, setReason] = useState("");
  return (
    <ModalShell title="Revoke advisory" onClose={onClose}>
      <div className="p-6 space-y-3">
        <p className="text-[13px]" style={{ color: "var(--color-body)" }}>
          Revocation marks the advisory as withdrawn and surfaces the reason
          publicly. Use for false positives, superseded guidance, or content
          retractions.
        </p>
        <Field label="Reason" required>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            className="w-full px-3 py-2 text-[13px] resize-none"
            style={inputStyle}
            placeholder="Superseded by ADV-2026-05; original CVE later withdrawn by upstream."
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={() => onSubmit(reason)}
        submitLabel="Revoke"
        submitTone="error"
        disabled={!reason.trim()}
      />
    </ModalShell>
  );
}


function TriageBar({ advisory }: { advisory: AdvisoryResponse }) {
  const { toast } = useToast();
  const [state, setState] = useState(advisory.triage_state || "new");
  const states = [
    { id: "new", label: "New", color: "#6B7280" },
    { id: "acknowledged", label: "Acknowledged", color: "#007B8A" },
    { id: "in_remediation", label: "In remediation", color: "#B76E00" },
    { id: "resolved", label: "Resolved", color: "#007B55" },
    { id: "dismissed", label: "Dismissed", color: "#6B21A8" },
  ];
  return (
    <div className="flex items-center gap-2 px-3 py-2" style={{ background: "var(--color-surface)", border: "1px solid var(--color-border)", borderRadius: 5 }}>
      <span className="text-[11px] font-bold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
        Triage:
      </span>
      {states.map((s) => (
        <button
          key={s.id}
          onClick={async () => {
            try {
              await api.news.triageAdvisory(advisory.id, s.id);
              setState(s.id);
              toast("success", `Moved to ${s.label}`);
            } catch (e) {
              toast("error", `Triage failed — ${String(e)}`);
            }
          }}
          className="h-7 px-2 text-[11px] font-bold transition-colors"
          style={{
            borderRadius: 3,
            border: state === s.id ? `1px solid ${s.color}` : "1px solid var(--color-border)",
            background: state === s.id ? `${s.color}15` : "var(--color-canvas)",
            color: state === s.id ? s.color : "var(--color-body)",
          }}
        >
          {s.label}
        </button>
      ))}
    </div>
  );
}


function AffectedExposuresPanel({ advisoryId }: { advisoryId: string }) {
  const [orgId, setOrgId] = useState<string | null>(null);
  const [rows, setRows] = useState<{ id: string; cve_ids: string[]; severity: string | null; asset_value: string | null; title: string | null }[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getCurrentOrg().then((o) => setOrgId(o?.id || null)).catch(() => setOrgId(null));
  }, []);

  useEffect(() => {
    if (!orgId) return;
    setLoading(true);
    api.news.affectedAssets(advisoryId, orgId)
      .then(setRows)
      .catch(() => setRows([]))
      .finally(() => setLoading(false));
  }, [advisoryId, orgId]);

  return (
    <Section>
      <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
        <h3 className="text-[12px] font-bold uppercase tracking-[0.1em]" style={{ color: "var(--color-body)" }}>
          Affected exposures in your environment
        </h3>
      </div>
      <div className="px-4 py-3">
        {loading ? (
          <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>Checking your exposures…</p>
        ) : rows.length === 0 ? (
          <p className="text-[12px] italic" style={{ color: "var(--color-muted)" }}>
            No exposures in your tracked assets reference these CVEs.
          </p>
        ) : (
          <ul className="space-y-1.5">
            {rows.map((r) => (
              <li key={r.id} className="flex items-center gap-3 text-[12px]" style={{ color: "var(--color-body)" }}>
                {r.severity && (
                  <span
                    className="inline-flex h-[18px] px-1.5 text-[10px] font-bold uppercase"
                    style={{ borderRadius: 3, background: "rgba(255,86,48,0.05)", color: "#B71D18" }}
                  >
                    {r.severity}
                  </span>
                )}
                {r.asset_value && <span className="font-mono">{r.asset_value}</span>}
                <span className="font-semibold flex-1 truncate" style={{ color: "var(--color-ink)" }}>{r.title}</span>
                <span className="text-[10px]" style={{ color: "var(--color-muted)" }}>
                  {r.cve_ids.slice(0, 2).join(", ")}
                  {r.cve_ids.length > 2 && ` +${r.cve_ids.length - 2}`}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Section>
  );
}


function CommentsPanel({ advisoryId }: { advisoryId: string }) {
  const { toast } = useToast();
  const [items, setItems] = useState<{ id: string; body: string; author_user_id: string | null; created_at: string }[]>([]);
  const [draft, setDraft] = useState("");
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    try {
      const r = await api.news.listAdvisoryComments(advisoryId);
      setItems(r);
    } finally {
      setLoading(false);
    }
  }, [advisoryId]);
  useEffect(() => { void load(); }, [load]);

  return (
    <Section>
      <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
        <h3 className="text-[12px] font-bold uppercase tracking-[0.1em]" style={{ color: "var(--color-body)" }}>
          Comments
        </h3>
      </div>
      <div className="px-4 py-3 space-y-3">
        <div className="flex gap-2">
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="Add a comment…"
            className="flex-1 h-9 px-3 text-[13px]"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-ink)",
            }}
          />
          <button
            disabled={!draft.trim()}
            onClick={async () => {
              try {
                await api.news.addAdvisoryComment(advisoryId, draft.trim());
                setDraft("");
                await load();
              } catch (e) {
                toast("error", `Comment failed — ${String(e)}`);
              }
            }}
            className="h-9 px-3 text-[12px] font-semibold disabled:opacity-50"
            style={{ borderRadius: 4, background: "var(--color-accent)", color: "#fff" }}
          >
            Post
          </button>
        </div>
        {loading ? (
          <p className="text-[12px]" style={{ color: "var(--color-muted)" }}>Loading…</p>
        ) : items.length === 0 ? (
          <p className="text-[12px] italic" style={{ color: "var(--color-muted)" }}>No comments yet.</p>
        ) : (
          <ul className="space-y-2">
            {items.map((c) => (
              <li
                key={c.id}
                className="p-2"
                style={{ borderRadius: 4, background: "var(--color-surface)" }}
              >
                <p className="text-[12px]" style={{ color: "var(--color-body)" }}>{c.body}</p>
                <p className="text-[10px] mt-1" style={{ color: "var(--color-muted)" }}>
                  {new Date(c.created_at).toISOString().replace("T", " ").slice(0, 19)}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Section>
  );
}
