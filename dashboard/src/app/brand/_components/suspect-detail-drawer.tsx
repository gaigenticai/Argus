"use client";

import { Fragment, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Camera, ExternalLink, Sparkles } from "lucide-react";

import {
  api,
  type BrandActionListItem,
  type BrandSuspectWhois,
  type LiveProbeResponse,
  type SuspectDomainResponse,
} from "@/lib/api";
import { Section } from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";

import {
  PROBE_VERDICT_LABEL,
  RECOMMENDATION_LABEL,
  RECOMMENDATION_TONE,
  riskSignalLabel,
  sourceLabel,
} from "./labels";


/** Right-side drawer with everything Argus knows about one suspect:
 *  the suspect row itself, every probe ever run against it, every
 *  brand-action the agent has emitted, and inline actions for
 *  re-probe / re-defend / transition / allowlist.
 *
 *  Drawer-style (not a modal) so the analyst can scroll the
 *  underlying suspect list while reviewing one entry.
 */
export function SuspectDetailDrawer({
  suspect,
  onClose,
  onProbe,
  onDefend,
  onTransition,
  onAllowlist,
}: {
  suspect: SuspectDomainResponse;
  onClose: () => void;
  onProbe: () => void;
  onDefend: () => void;
  onTransition: () => void;
  onAllowlist?: () => void;
}) {
  const { toast } = useToast();
  const [probes, setProbes] = useState<LiveProbeResponse[] | null>(null);
  const [actions, setActions] = useState<BrandActionListItem[] | null>(null);
  // WHOIS — lazy. ``undefined`` = not asked yet, ``null`` = fetch
  // failed, otherwise the full record. Server-side cache makes
  // re-opens cheap.
  const [whois, setWhois] = useState<BrandSuspectWhois | null | undefined>(undefined);
  const [whoisLoading, setWhoisLoading] = useState(false);

  const load = useCallback(async () => {
    try {
      const [pp, aa, ww] = await Promise.all([
        api.brand.listProbesForSuspect(suspect.id, 20).catch(() => [] as LiveProbeResponse[]),
        api.brandActions
          .list({ suspect_domain_id: suspect.id, limit: 20 })
          .catch(() => [] as BrandActionListItem[]),
        // WHOIS is best-effort — cache hit returns instantly, miss
        // does the full lookup (8s timeout). Don't block drawer
        // render on it; failures decay to null.
        api.brand.getSuspectWhois(suspect.id).catch(() => null),
      ]);
      setProbes(pp);
      setActions(aa);
      setWhois(ww);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load suspect detail",
      );
    }
  }, [suspect.id, toast]);

  const refreshWhois = useCallback(async () => {
    setWhoisLoading(true);
    try {
      const w = await api.brand.getSuspectWhois(suspect.id, true);
      setWhois(w);
      toast("success", "WHOIS refreshed");
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "WHOIS lookup failed");
    } finally {
      setWhoisLoading(false);
    }
  }, [suspect.id, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  // ESC closes.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div
        onClick={onClose}
        aria-hidden
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,0,0,0.32)",
          zIndex: 70,
        }}
      />
      <aside
        role="dialog"
        aria-label="Suspect detail"
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width: "min(560px, 100vw)",
          background: "var(--color-canvas)",
          borderLeft: "1px solid var(--color-border)",
          zIndex: 71,
          display: "flex",
          flexDirection: "column",
          boxShadow: "-12px 0 32px rgba(0,0,0,0.18)",
        }}
      >
        <header
          style={{
            padding: "16px 20px",
            borderBottom: "1px solid var(--color-border)",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 12,
          }}
        >
          <div style={{ minWidth: 0, flex: 1 }}>
            <div
              style={{
                fontFamily: "monospace",
                fontSize: 14,
                color: "var(--color-ink)",
                fontWeight: 600,
                wordBreak: "break-all",
              }}
            >
              {suspect.domain}
            </div>
            <div
              style={{
                marginTop: 4,
                fontSize: 11.5,
                color: "var(--color-muted)",
                display: "flex",
                gap: 6,
                flexWrap: "wrap",
              }}
            >
              <span
                style={{
                  fontFamily: "monospace",
                  color:
                    suspect.similarity >= 0.9
                      ? "#B71D18"
                      : suspect.similarity >= 0.75
                        ? "#B76E00"
                        : "var(--color-body)",
                  fontWeight: 700,
                }}
              >
                {Math.round(suspect.similarity * 100)}%
              </span>
              <span>·</span>
              <span>matches {suspect.matched_term_value}</span>
              <span>·</span>
              <span>{sourceLabel(suspect.source)}</span>
              <span>·</span>
              <span>{suspect.state}</span>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            title="Close (Esc)"
            style={{
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
              borderRadius: 4,
              width: 28,
              height: 28,
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              fontSize: 14,
              flexShrink: 0,
            }}
          >
            ×
          </button>
        </header>

        <div style={{ flex: 1, overflowY: "auto", padding: "14px 20px", display: "flex", flexDirection: "column", gap: 18 }}>
          {/* DNS facts */}
          <section>
            <h4
              style={{
                fontSize: 10.5,
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.08em",
                color: "var(--color-muted)",
                marginBottom: 6,
              }}
            >
              DNS
            </h4>
            <dl style={{ display: "grid", gridTemplateColumns: "100px 1fr", rowGap: 6, columnGap: 12, fontSize: 12, margin: 0 }}>
              <dt style={{ color: "var(--color-muted)" }}>resolves</dt>
              <dd style={{ margin: 0, fontFamily: "monospace", color: "var(--color-ink)" }}>
                {suspect.is_resolvable === null
                  ? "unknown"
                  : suspect.is_resolvable
                    ? "yes"
                    : "no"}
              </dd>
              <dt style={{ color: "var(--color-muted)" }}>A records</dt>
              <dd style={{ margin: 0, fontFamily: "monospace", color: "var(--color-ink)" }}>
                {suspect.a_records.length > 0
                  ? suspect.a_records.join(", ")
                  : <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>none</span>}
              </dd>
              <dt style={{ color: "var(--color-muted)" }}>MX</dt>
              <dd style={{ margin: 0, fontFamily: "monospace", color: "var(--color-ink)" }}>
                {suspect.mx_records.length > 0
                  ? suspect.mx_records.join(", ")
                  : <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>none</span>}
              </dd>
              <dt style={{ color: "var(--color-muted)" }}>NS</dt>
              <dd style={{ margin: 0, fontFamily: "monospace", color: "var(--color-ink)" }}>
                {suspect.nameservers.length > 0
                  ? suspect.nameservers.join(", ")
                  : <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>none</span>}
              </dd>
              <dt style={{ color: "var(--color-muted)" }}>first seen</dt>
              <dd style={{ margin: 0, color: "var(--color-ink)" }}>
                {timeAgo(suspect.first_seen_at)}
              </dd>
              <dt style={{ color: "var(--color-muted)" }}>last seen</dt>
              <dd style={{ margin: 0, color: "var(--color-ink)" }}>
                {timeAgo(suspect.last_seen_at)}
              </dd>
            </dl>
          </section>

          {/* WHOIS — lazy, cached server-side for 24h */}
          <section>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
              <h4
                style={{
                  fontSize: 10.5,
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  color: "var(--color-muted)",
                  margin: 0,
                }}
              >
                WHOIS
                {whois?.cached ? (
                  <span style={{ marginLeft: 6, fontSize: 9, color: "var(--color-muted)", fontWeight: 600 }}>
                    cached
                  </span>
                ) : null}
              </h4>
              <button
                onClick={refreshWhois}
                disabled={whoisLoading}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "var(--color-accent)",
                  fontSize: 10.5,
                  cursor: "pointer",
                  padding: 0,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  fontWeight: 700,
                }}
              >
                {whoisLoading ? "Refreshing…" : "Refresh"}
              </button>
            </div>
            {whois === undefined ? (
              <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>Loading…</p>
            ) : whois === null ? (
              <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>
                WHOIS unavailable.{" "}
                <button
                  onClick={refreshWhois}
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "var(--color-accent)",
                    cursor: "pointer",
                    padding: 0,
                    textDecoration: "underline",
                    fontSize: 12,
                  }}
                >
                  Try fresh lookup
                </button>
                .
              </p>
            ) : (
              <dl
                style={{
                  display: "grid",
                  gridTemplateColumns: "120px 1fr",
                  rowGap: 6,
                  columnGap: 12,
                  fontSize: 12,
                  margin: 0,
                }}
              >
                {(
                  [
                    ["Registrar", whois.registrar],
                    ["Registrant", whois.registrant_name],
                    ["Org", whois.registrant_org],
                    ["Email", whois.registrant_email],
                    ["Country", whois.registrant_country],
                    ["Abuse contact", whois.abuse_email],
                    ["Registered", whois.registered_at],
                    ["Updated", whois.updated_at],
                    ["Expires", whois.expires_at],
                  ] as Array<[string, string | null]>
                ).map(([label, value]) => (
                  value ? (
                    <Fragment key={label}>
                      <dt style={{ color: "var(--color-muted)" }}>{label}</dt>
                      <dd
                        style={{
                          margin: 0,
                          fontFamily: ["Email", "Abuse contact", "Registrar"].includes(label)
                            ? "monospace"
                            : undefined,
                          color: "var(--color-ink)",
                          wordBreak: "break-all",
                        }}
                      >
                        {value}
                      </dd>
                    </Fragment>
                  ) : null
                ))}
                {!whois.registrar
                  && !whois.registrant_email
                  && !whois.abuse_email
                  && !whois.registered_at ? (
                  <dd
                    style={{
                      gridColumn: "1 / -1",
                      margin: 0,
                      color: "var(--color-muted)",
                      fontStyle: "italic",
                    }}
                  >
                    WHOIS came back empty (registrar may have privacy
                    proxy or rate-limited the lookup).
                  </dd>
                ) : null}
              </dl>
            )}
          </section>

          {/* Live probes */}
          <section>
            <h4
              style={{
                fontSize: 10.5,
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.08em",
                color: "var(--color-muted)",
                marginBottom: 6,
              }}
            >
              Live probes ({probes?.length ?? 0})
            </h4>
            {probes === null ? (
              <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>Loading…</p>
            ) : probes.length === 0 ? (
              <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>
                Never probed yet.
              </p>
            ) : (
              <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 4 }}>
                {probes.slice(0, 8).map((p) => {
                  const tone =
                    p.verdict === "phishing" ? "#B71D18"
                      : p.verdict === "suspicious" ? "#B76E00"
                      : p.verdict === "benign" ? "#007B55"
                      : "var(--color-muted)";
                  return (
                    <li
                      key={p.id}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        padding: "6px 8px",
                        border: "1px solid var(--color-border)",
                        borderRadius: 4,
                        background: "var(--color-canvas)",
                      }}
                    >
                      <span
                        style={{
                          fontFamily: "monospace",
                          fontSize: 10,
                          fontWeight: 700,
                          color: tone,
                          width: 80,
                          textTransform: "uppercase",
                          letterSpacing: "0.06em",
                          flexShrink: 0,
                        }}
                      >
                        {PROBE_VERDICT_LABEL[p.verdict] || p.verdict}
                      </span>
                      <span
                        style={{
                          fontSize: 11.5,
                          color: "var(--color-body)",
                          flex: 1,
                          minWidth: 0,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                        title={p.title || ""}
                      >
                        {p.title || (p.url || p.final_url || "")}
                      </span>
                      <span style={{ fontFamily: "monospace", fontSize: 10.5, color: "var(--color-muted)" }}>
                        {timeAgo(p.fetched_at)}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>

          {/* Brand-actions */}
          <section>
            <h4
              style={{
                fontSize: 10.5,
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.08em",
                color: "var(--color-muted)",
                marginBottom: 6,
              }}
            >
              Brand Defender runs ({actions?.length ?? 0})
            </h4>
            {actions === null ? (
              <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>Loading…</p>
            ) : actions.length === 0 ? (
              <p style={{ fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>
                The agent hasn&apos;t run on this suspect yet.
              </p>
            ) : (
              <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 4 }}>
                {actions.map((a) => (
                  <li
                    key={a.id}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      padding: "6px 8px",
                      border: "1px solid var(--color-border)",
                      borderRadius: 4,
                      background: "var(--color-canvas)",
                    }}
                  >
                    <span
                      style={{
                        padding: "1px 6px",
                        borderRadius: 3,
                        background: "var(--color-surface-muted)",
                        color: a.recommendation
                          ? RECOMMENDATION_TONE[a.recommendation] || "var(--color-body)"
                          : "var(--color-muted)",
                        fontWeight: 700,
                        textTransform: "uppercase",
                        letterSpacing: "0.04em",
                        fontSize: 9.5,
                      }}
                    >
                      {a.recommendation
                        ? RECOMMENDATION_LABEL[a.recommendation] || a.recommendation
                        : a.status}
                    </span>
                    {typeof a.confidence === "number" ? (
                      <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--color-body)" }}>
                        {Math.round(a.confidence * 100)}%
                      </span>
                    ) : null}
                    <span style={{ fontSize: 11, color: "var(--color-muted)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={a.risk_signals.map((s) => riskSignalLabel(s)).join(", ")}>
                      {a.risk_signals.length} signal{a.risk_signals.length === 1 ? "" : "s"}
                    </span>
                    <Link
                      href={`/brand?tab=defender&id=${a.id}`}
                      style={{
                        color: "var(--color-accent)",
                        textDecoration: "none",
                        fontSize: 11,
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 3,
                      }}
                    >
                      Open
                      <ExternalLink className="w-3 h-3" />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        {/* Action footer */}
        <footer
          style={{
            padding: "12px 20px",
            borderTop: "1px solid var(--color-border)",
            display: "flex",
            alignItems: "center",
            gap: 8,
            justifyContent: "flex-end",
            flexWrap: "wrap",
          }}
        >
          {onAllowlist ? (
            <button
              onClick={onAllowlist}
              className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
              style={{
                borderRadius: 4,
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-body)",
              }}
              title="Add this domain to the subsidiary allowlist — auto-dismiss future matches"
            >
              Add to allowlist
            </button>
          ) : null}
          <button
            onClick={onTransition}
            className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            Transition
          </button>
          <button
            onClick={onProbe}
            className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              color: "var(--color-body)",
            }}
          >
            <Camera className="w-3 h-3" />
            Probe
          </button>
          <button
            onClick={onDefend}
            className="inline-flex items-center gap-1.5 h-8 px-3 text-[12px] font-bold transition-colors"
            style={{
              borderRadius: 4,
              border: "1px solid var(--color-accent)",
              background: "var(--color-accent)",
              color: "var(--color-on-dark)",
            }}
          >
            <Sparkles className="w-3 h-3" />
            Defend
          </button>
        </footer>
      </aside>
    </>
  );
}
