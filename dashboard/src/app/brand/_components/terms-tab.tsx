"use client";

import { useCallback, useEffect, useState } from "react";
import {
  CheckCircle2,
  Plus,
  ScanSearch,
  Tag as TagIcon,
  Trash2,
  Wand2,
} from "lucide-react";
import {
  api,
  type BrandTermKindValue,
  type BrandTermResponse,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Field,
  ModalFooter,
  ModalShell,
  Section,
  SkeletonRows,
  Th,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { useBrandContext } from "./use-brand-context";

const inputStyle: React.CSSProperties = {
  width: "100%",
  height: "40px",
  padding: "0 12px",
  borderRadius: "4px",
  border: "1px solid var(--color-border)",
  background: "var(--color-canvas)",
  color: "var(--color-ink)",
  fontSize: "13px",
  outline: "none",
};

const KIND_LABEL: Record<BrandTermKindValue, string> = {
  apex_domain: "APEX",
  name: "NAME",
  product: "PRODUCT",
};

// Zapier design system chip styles per kind
const KIND_CHIP_STYLE: Record<BrandTermKindValue, React.CSSProperties> = {
  apex_domain: {
    border: "1px solid rgba(255,79,0,0.4)",
    background: "rgba(255,79,0,0.1)",
    color: "var(--color-accent)",
  },
  name: {
    border: "1px solid rgba(0,187,217,0.4)",
    background: "rgba(0,187,217,0.1)",
    color: "#007B8A",
  },
  product: {
    border: "1px solid rgba(0,167,111,0.4)",
    background: "rgba(0,167,111,0.1)",
    color: "#007B55",
  },
};

export function TermsTab() {
  const { orgId, bumpRefresh } = useBrandContext();
  const { toast } = useToast();
  const [terms, setTerms] = useState<BrandTermResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [feedIngest, setFeedIngest] = useState(false);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const t = await api.brand.listTerms(orgId);
      setTerms(t);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load brand terms",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const removeTerm = async (t: BrandTermResponse) => {
    if (!confirm(`Remove brand term "${t.value}"?`)) return;
    try {
      await api.brand.deleteTerm(t.id);
      toast("success", `Removed ${t.value}`);
      bumpRefresh();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to remove term",
      );
    }
  };

  const runScan = async () => {
    setScanning(true);
    try {
      const r = await api.brand.runScan({ organization_id: orgId });
      toast(
        "success",
        `Scan complete · ${r.suspects_created} new, ${r.suspects_seen_again} touched, ${r.permutations_generated} candidates`,
      );
      bumpRefresh();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Scan failed",
      );
    } finally {
      setScanning(false);
    }
  };

  const ingestFeed = async (
    candidates: string[],
    source:
      | "phishtank"
      | "openphish"
      | "urlhaus"
      | "manual" = "manual",
  ) => {
    setFeedIngest(true);
    try {
      const r = await api.brand.runFeedIngest({
        organization_id: orgId,
        candidates,
        source,
      });
      toast(
        "success",
        `Ingested ${candidates.length} candidates · ${r.suspects_created} new, ${r.suspects_seen_again} touched`,
      );
      bumpRefresh();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Feed ingest failed",
      );
    } finally {
      setFeedIngest(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Brand terms registry */}
      <Section>
        <div
          className="px-4 py-3 flex items-center justify-between flex-wrap gap-2"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <div>
            <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
              Brand terms
            </h3>
            <p style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "2px" }}>
              The seed strings every brand-protection scanner uses.
              <span style={{ fontWeight: 700, color: "var(--color-body)" }}> APEX</span> drives the
              typosquat scanner;
              <span style={{ fontWeight: 700, color: "var(--color-body)" }}> NAME</span> drives
              social impersonation, mobile-app, and fraud scoring;
              <span style={{ fontWeight: 700, color: "var(--color-body)" }}> PRODUCT</span> is for
              keyword filters.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <ScanButton
              onClick={runScan}
              disabled={scanning || terms.length === 0}
              scanning={scanning}
            />
            <PrimaryButton onClick={() => setShowAdd(true)}>
              <Plus className="w-3.5 h-3.5" />
              Add term
            </PrimaryButton>
          </div>
        </div>

        {loading ? (
          <SkeletonRows rows={3} columns={4} />
        ) : terms.length === 0 ? (
          <Empty
            icon={TagIcon}
            title="No brand terms yet"
            description="Add at least one APEX domain (your real homepage, e.g. argusbank.demo) and one NAME (e.g. argus). The brand monitor needs both to surface meaningful matches."
            action={
              <PrimaryButton onClick={() => setShowAdd(true)}>
                <Plus className="w-4 h-4" />
                Add brand term
              </PrimaryButton>
            }
          />
        ) : (
          <table className="w-full">
            <thead>
              <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                <Th align="left" className="pl-4 w-[100px]">
                  Kind
                </Th>
                <Th align="left">Value</Th>
                <Th align="left">Keywords</Th>
                <Th align="left" className="w-[100px]">
                  Active
                </Th>
                <Th align="left" className="w-[120px]">
                  Added
                </Th>
                <Th align="right" className="pr-4 w-[80px]">
                  &nbsp;
                </Th>
              </tr>
            </thead>
            <tbody>
              {terms.map((t) => (
                <TermRow key={t.id} t={t} onRemove={() => removeTerm(t)} />
              ))}
            </tbody>
          </table>
        )}
      </Section>

      {/* Manual feed ingest */}
      <Section>
        <div
          className="px-4 py-3"
          style={{ borderBottom: "1px solid var(--color-border)" }}
        >
          <h3 style={{ fontSize: "13px", fontWeight: 700, color: "var(--color-ink)" }}>
            Manual feed ingest
          </h3>
          <p style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "2px" }}>
            Paste candidate domains for ad-hoc analyst checks. Live phishing
            feeds (PhishTank, OpenPhish, URLhaus) auto-ingest hourly via the
            worker.
          </p>
        </div>
        <FeedIngestPanel
          onSubmit={ingestFeed}
          submitting={feedIngest}
        />
      </Section>

      {showAdd && orgId && (
        <AddTermModal
          orgId={orgId}
          onClose={() => setShowAdd(false)}
          onAdded={() => {
            setShowAdd(false);
            bumpRefresh();
          }}
        />
      )}
    </div>
  );
}

function TermRow({ t, onRemove }: { t: BrandTermResponse; onRemove: () => void }) {
  const [hovered, setHovered] = useState(false);
  const [btnHov, setBtnHov] = useState(false);
  return (
    <tr
      style={{
        height: "48px",
        borderBottom: "1px solid var(--color-border)",
        background: hovered ? "var(--color-surface)" : "transparent",
        transition: "background 0.15s",
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <td className="pl-4">
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            height: "20px",
            padding: "0 6px",
            borderRadius: "4px",
            fontSize: "10px",
            fontWeight: 700,
            letterSpacing: "0.06em",
            ...KIND_CHIP_STYLE[t.kind],
          }}
        >
          {KIND_LABEL[t.kind]}
        </span>
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "13px", color: "var(--color-ink)" }}>
        {t.value}
      </td>
      <td className="px-3">
        {t.keywords.length === 0 ? (
          <span style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>—</span>
        ) : (
          <div className="flex flex-wrap gap-1">
            {t.keywords.map((k) => (
              <span
                key={k}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  height: "18px",
                  padding: "0 6px",
                  borderRadius: "4px",
                  background: "var(--color-surface-muted)",
                  fontSize: "10.5px",
                  fontFamily: "monospace",
                  color: "var(--color-body)",
                }}
              >
                {k}
              </span>
            ))}
          </div>
        )}
      </td>
      <td className="px-3">
        {t.is_active ? (
          <span className="inline-flex items-center gap-1" style={{ fontSize: "11.5px", fontWeight: 700, color: "#007B55" }}>
            <CheckCircle2 style={{ width: "12px", height: "12px" }} />
            ACTIVE
          </span>
        ) : (
          <span style={{ fontSize: "11.5px", fontWeight: 700, color: "var(--color-muted)" }}>
            INACTIVE
          </span>
        )}
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(t.created_at)}
      </td>
      <td className="pr-4" style={{ textAlign: "right" }}>
        <button
          onClick={onRemove}
          onMouseEnter={() => setBtnHov(true)}
          onMouseLeave={() => setBtnHov(false)}
          style={{
            padding: "6px",
            borderRadius: "4px",
            border: "none",
            background: btnHov ? "rgba(255,86,48,0.1)" : "none",
            color: btnHov ? "#FF5630" : "var(--color-muted)",
            cursor: "pointer",
            transition: "background 0.15s, color 0.15s",
          }}
          aria-label="Remove"
        >
          <Trash2 style={{ width: "14px", height: "14px" }} />
        </button>
      </td>
    </tr>
  );
}

function PrimaryButton({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        height: "36px",
        padding: "0 12px",
        borderRadius: "4px",
        fontSize: "13px",
        fontWeight: 700,
        background: hov ? "#e64600" : "var(--color-accent)",
        color: "var(--color-on-dark)",
        border: "none",
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      {children}
    </button>
  );
}

function ScanButton({ onClick, disabled, scanning }: { onClick: () => void; disabled: boolean; scanning: boolean }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        height: "36px",
        padding: "0 12px",
        borderRadius: "4px",
        fontSize: "13px",
        fontWeight: 700,
        border: "1px solid var(--color-border)",
        background: hov && !disabled ? "var(--color-surface-muted)" : "var(--color-canvas)",
        color: "var(--color-body)",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        transition: "background 0.15s",
      }}
    >
      <ScanSearch className={`w-3.5 h-3.5${scanning ? " animate-pulse" : ""}`} />
      {scanning ? "Scanning…" : "Run typosquat scan"}
    </button>
  );
}

function AddTermModal({
  orgId,
  onClose,
  onAdded,
}: {
  orgId: string;
  onClose: () => void;
  onAdded: () => void;
}) {
  const { toast } = useToast();
  const [kind, setKind] = useState<BrandTermKindValue>("apex_domain");
  const [value, setValue] = useState("");
  const [keywords, setKeywords] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    const v = value.trim().toLowerCase();
    if (!v || busy) return;
    setBusy(true);
    try {
      await api.brand.createTerm({
        organization_id: orgId,
        kind,
        value: v,
        keywords: keywords
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      });
      toast("success", `Added ${kind} term: ${v}`);
      onAdded();
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to add brand term",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <ModalShell title="Add brand term" onClose={onClose}>
      <div className="p-6 space-y-5">
        <Field label="Kind" required>
          <div className="grid grid-cols-3 gap-1.5">
            {(["apex_domain", "name", "product"] as BrandTermKindValue[]).map(
              (k) => {
                const active = kind === k;
                return (
                  <button
                    key={k}
                    onClick={() => setKind(k)}
                    style={{
                      height: "40px",
                      borderRadius: "4px",
                      border: active ? "1px solid var(--color-border-strong)" : "1px solid var(--color-border)",
                      background: "var(--color-canvas)",
                      boxShadow: active ? "var(--color-border-strong) 0px 0px 0px 2px inset" : "none",
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "2px",
                      fontSize: "11px",
                      fontWeight: 700,
                      letterSpacing: "0.04em",
                      color: active ? "var(--color-ink)" : "var(--color-body)",
                      cursor: "pointer",
                      transition: "all 0.15s",
                    }}
                  >
                    {KIND_LABEL[k]}
                  </button>
                );
              },
            )}
          </div>
        </Field>
        <Field
          label="Value"
          required
          hint={
            kind === "apex_domain"
              ? "Apex domain only (no scheme, no path), e.g. argusbank.demo"
              : kind === "name"
              ? "The brand or product name as a string, e.g. argus"
              : "Product token, e.g. argus-pay"
          }
        >
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            style={{ ...inputStyle, fontFamily: "monospace" }}
            placeholder={
              kind === "apex_domain"
                ? "argusbank.demo"
                : kind === "name"
                ? "argus"
                : "argus-pay"
            }
            autoFocus
          />
        </Field>
        <Field
          label="Keywords"
          hint="Optional comma-separated list. Surfaces in fraud-scoring rationale."
        >
          <input
            value={keywords}
            onChange={(e) => setKeywords(e.target.value)}
            style={inputStyle}
            placeholder="banking, login, support"
          />
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Adding…" : "Add term"}
        disabled={!value.trim() || busy}
      />
    </ModalShell>
  );
}

function FeedIngestPanel({
  onSubmit,
  submitting,
}: {
  onSubmit: (candidates: string[], source?: "manual") => Promise<void>;
  submitting: boolean;
}) {
  const [text, setText] = useState("");
  const [btnHov, setBtnHov] = useState(false);

  const handle = () => {
    const lines = text
      .split(/[\n,\s]+/)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    if (lines.length === 0) return;
    onSubmit(lines, "manual").then(() => setText(""));
  };

  return (
    <div className="p-4">
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={5}
        placeholder="argus-secure-login.com&#10;login-argus.io&#10;argus-bank-customer-support.net"
        style={{
          width: "100%",
          padding: "8px 12px",
          borderRadius: "4px",
          border: "1px solid var(--color-border)",
          background: "var(--color-canvas)",
          color: "var(--color-ink)",
          fontSize: "13px",
          fontFamily: "monospace",
          outline: "none",
          resize: "none",
        }}
      />
      <div className="flex items-center justify-between mt-2.5">
        <p style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>
          One per line. Domains only — schemes/paths are stripped during ingest.
        </p>
        <button
          onClick={handle}
          disabled={!text.trim() || submitting}
          onMouseEnter={() => setBtnHov(true)}
          onMouseLeave={() => setBtnHov(false)}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            height: "36px",
            padding: "0 12px",
            borderRadius: "4px",
            fontSize: "13px",
            fontWeight: 700,
            background: btnHov && !submitting && text.trim() ? "#e64600" : "var(--color-accent)",
            color: "var(--color-on-dark)",
            border: "none",
            cursor: !text.trim() || submitting ? "not-allowed" : "pointer",
            opacity: !text.trim() || submitting ? 0.5 : 1,
            transition: "background 0.15s",
          }}
        >
          <Wand2 className="w-3.5 h-3.5" />
          {submitting ? "Ingesting…" : "Ingest candidates"}
        </button>
      </div>
    </div>
  );
}
