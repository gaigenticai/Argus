"use client";

import { useCallback, useEffect, useState } from "react";
import { Camera, ExternalLink, ImageOff, Sparkles } from "lucide-react";
import {
  api,
  type LiveProbeResponse,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  PaginationFooter,
  Section,
  Select,
  StatePill,
  type StateTone,
} from "@/components/shared/page-primitives";
import { formatDate, timeAgo } from "@/lib/utils";
import { useBrandContext } from "./use-brand-context";

const VERDICT_TONE: Record<string, StateTone> = {
  phishing: "error-strong",
  suspicious: "warning",
  clean: "success",
  unreachable: "muted",
  pending: "neutral",
};

const VERDICT_OPTIONS = [
  { value: "all", label: "Any verdict" },
  { value: "phishing", label: "Phishing" },
  { value: "suspicious", label: "Suspicious" },
  { value: "clean", label: "Clean" },
  { value: "unreachable", label: "Unreachable" },
];

const PAGE_LIMIT = 24;

export function ProbesTab() {
  const { orgId} = useBrandContext();
  const { toast } = useToast();
  const [rows, setRows] = useState<LiveProbeResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [verdict, setVerdict] = useState("all");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<LiveProbeResponse | null>(null);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const { data, page } = await api.brand.listProbes({
        organization_id: orgId,
        verdict: verdict === "all" ? undefined : verdict,
        limit: PAGE_LIMIT,
        offset,
      });
      setRows(data);
      setTotal(page.total ?? data.length);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load probes",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, verdict, offset, toast]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="Verdict"
          value={verdict}
          options={VERDICT_OPTIONS}
          onChange={(v) => {
            setVerdict(v);
            setOffset(0);
          }}
        />
        <p style={{ fontSize: "12px", color: "var(--color-muted)", marginLeft: "auto", fontFamily: "monospace" }}>
          {total} probe{total === 1 ? "" : "s"} · newest first
        </p>
      </div>

      <Section>
        {loading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3 p-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <div
                key={i}
                style={{
                  borderRadius: "5px",
                  border: "1px solid var(--color-border)",
                  height: "260px",
                  background: "var(--color-surface)",
                  animationDelay: `${i * 60}ms`,
                }}
                className="animate-pulse"
              />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <Empty
            icon={Camera}
            title={
              verdict !== "all"
                ? `No ${verdict} probes`
                : "No live probes yet"
            }
            description="Probes are recorded when an analyst (or auto-elevation rule) hits a suspect domain. Run a probe from Suspect domains → PROBE."
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3 p-3">
            {rows.map((p) => (
              <ProbeCard
                key={p.id}
                probe={p}
                onClick={() => setSelected(p)}
              />
            ))}
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

      {selected && (
        <ProbeDetailDrawer
          probe={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

function ProbeCard({
  probe,
  onClick,
}: {
  probe: LiveProbeResponse;
  onClick: () => void;
}) {
  const [hovered, setHovered] = useState(false);
  const tone = VERDICT_TONE[probe.verdict] || "neutral";
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        textAlign: "left",
        borderRadius: "5px",
        border: `1px solid ${hovered ? "var(--color-border-strong)" : "var(--color-border)"}`,
        background: "var(--color-canvas)",
        overflow: "hidden",
        transition: "border-color 0.15s",
        cursor: "pointer",
        display: "block",
        width: "100%",
      }}
    >
      <ScreenshotPreview sha={probe.screenshot_evidence_sha256} />
      <div className="px-3 py-3 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <StatePill label={probe.verdict} tone={tone} />
          <span style={{ fontFamily: "monospace", fontSize: "10.5px", color: "var(--color-muted)" }}>
            {timeAgo(probe.fetched_at)}
          </span>
        </div>
        <div style={{ fontFamily: "monospace", fontSize: "12px", color: "var(--color-ink)" }} className="truncate">
          {probe.domain}
        </div>
        {probe.title ? (
          <div style={{ fontSize: "11.5px", color: "var(--color-body)" }} className="line-clamp-1">
            {probe.title}
          </div>
        ) : null}
        <div className="flex items-center gap-2 pt-1">
          <ConfidenceBar value={probe.confidence} />
          <span style={{ fontFamily: "monospace", fontSize: "10.5px", color: "var(--color-muted)", marginLeft: "auto" }}>
            {probe.classifier_name}
          </span>
        </div>
      </div>
    </button>
  );
}

function ScreenshotPreview({ sha }: { sha: string | null }) {
  if (!sha) {
    return (
      <div
        className="aspect-[16/9] flex items-center justify-center"
        style={{ background: "var(--color-surface-muted)" }}
      >
        <div className="text-center">
          <ImageOff style={{ width: "24px", height: "24px", color: "var(--color-muted)", margin: "0 auto 4px" }} />
          <p style={{ fontSize: "10.5px", color: "var(--color-muted)", fontFamily: "monospace" }}>no screenshot</p>
        </div>
      </div>
    );
  }
  // The actual image bytes live in evidence vault; we render the
  // sha as a deterministic visual placeholder + label so the analyst
  // can confirm two probes hit the same content. Inline preview would
  // need a separate /evidence/{id}/inline endpoint per blob, which
  // belongs in the Evidence vault page, not on every probe card.
  const hue = parseInt(sha.slice(0, 6), 16) % 360;
  return (
    <div
      className="aspect-[16/9] flex items-end justify-end p-2 relative overflow-hidden"
      style={{
        background: `linear-gradient(135deg, hsl(${hue} 50% 90%), hsl(${(hue + 40) % 360} 50% 80%))`,
      }}
    >
      <span style={{
        fontFamily: "monospace",
        fontSize: "9.5px",
        letterSpacing: "0.06em",
        background: "rgba(255,254,251,0.7)",
        padding: "2px 6px",
        borderRadius: "3px",
        color: "var(--color-body)",
      }}>
        {sha.slice(0, 12)}…
      </span>
    </div>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value));
  const fillColor =
    pct >= 0.85 ? "#FF5630" : pct >= 0.6 ? "#FFAB00" : "#00B8D9";
  return (
    <div className="flex items-center gap-1.5">
      <div style={{ width: "48px", height: "4px", borderRadius: "9999px", background: "var(--color-surface-muted)", overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct * 100}%`, background: fillColor }} />
      </div>
      <span style={{ fontFamily: "monospace", fontSize: "10.5px", color: "var(--color-body)" }}>
        {pct.toFixed(2)}
      </span>
    </div>
  );
}

function ProbeDetailDrawer({
  probe,
  onClose,
}: {
  probe: LiveProbeResponse;
  onClose: () => void;
}) {
  const [urlHov, setUrlHov] = useState(false);
  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      style={{ background: "rgba(32,21,21,0.4)", backdropFilter: "blur(2px)" }}
      onClick={onClose}
    >
      <div
        style={{
          background: "var(--color-canvas)",
          width: "100%",
          maxWidth: "640px",
          height: "100%",
          overflowY: "auto",
        }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
      >
        <div
          className="px-6 py-5 sticky top-0 z-10 flex items-center justify-between"
          style={{ borderBottom: "1px solid var(--color-border)", background: "var(--color-canvas)" }}
        >
          <div>
            <div style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "var(--color-muted)" }}>
              Live probe
            </div>
            <h2 style={{ fontSize: "18px", fontWeight: 700, color: "var(--color-ink)", fontFamily: "monospace", marginTop: "2px" }}>
              {probe.domain}
            </h2>
          </div>
          <button
            onClick={onClose}
            style={{
              height: "32px",
              width: "32px",
              borderRadius: "4px",
              border: "none",
              background: "none",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "var(--color-body)",
              cursor: "pointer",
              fontSize: "18px",
            }}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <ScreenshotPreview sha={probe.screenshot_evidence_sha256} />

        <div className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-3">
            <DetailField label="Verdict">
              <StatePill
                label={probe.verdict}
                tone={VERDICT_TONE[probe.verdict] || "neutral"}
              />
            </DetailField>
            <DetailField label="Confidence">
              <ConfidenceBar value={probe.confidence} />
            </DetailField>
            <DetailField label="Classifier">
              <span style={{ fontFamily: "monospace", fontSize: "12.5px", color: "var(--color-ink)" }}>
                {probe.classifier_name}
              </span>
            </DetailField>
            <DetailField label="HTTP">
              <span style={{ fontFamily: "monospace", fontSize: "12.5px", color: "var(--color-ink)" }}>
                {probe.http_status ?? "—"}
              </span>
            </DetailField>
            <DetailField label="Fetched">
              <span style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-body)" }}>
                {formatDate(probe.fetched_at)}
              </span>
            </DetailField>
            <DetailField label="Title">
              <span style={{ fontSize: "12.5px", color: "var(--color-ink)" }}>
                {probe.title || (
                  <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>none</span>
                )}
              </span>
            </DetailField>
          </div>

          {probe.url ? (
            <DetailField label="Probed URL">
              <a
                href={probe.url}
                target="_blank"
                rel="noopener noreferrer nofollow"
                onMouseEnter={() => setUrlHov(true)}
                onMouseLeave={() => setUrlHov(false)}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "4px",
                  fontFamily: "monospace",
                  fontSize: "12px",
                  color: urlHov ? "var(--color-accent)" : "var(--color-body)",
                  transition: "color 0.15s",
                }}
              >
                {probe.url}
                <ExternalLink style={{ width: "12px", height: "12px" }} />
              </a>
            </DetailField>
          ) : null}

          {probe.final_url && probe.final_url !== probe.url ? (
            <DetailField label="Resolved to">
              <span style={{ fontFamily: "monospace", fontSize: "12px", color: "var(--color-ink)", wordBreak: "break-all" }}>
                {probe.final_url}
              </span>
            </DetailField>
          ) : null}

          {probe.signals.length > 0 ? (
            <DetailField label="Signals">
              <div className="flex flex-wrap gap-1">
                {probe.signals.map((s, i) => (
                  <span
                    key={`${s}-${i}`}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      height: "20px",
                      padding: "0 6px",
                      borderRadius: "4px",
                      background: "var(--color-surface-muted)",
                      fontSize: "10.5px",
                      fontFamily: "monospace",
                      color: "var(--color-body)",
                    }}
                  >
                    {s}
                  </span>
                ))}
              </div>
            </DetailField>
          ) : null}

          {probe.matched_brand_terms.length > 0 ? (
            <DetailField label="Matched brand terms">
              <div className="flex flex-wrap gap-1">
                {probe.matched_brand_terms.map((t) => (
                  <span
                    key={t}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      height: "20px",
                      padding: "0 6px",
                      borderRadius: "4px",
                      background: "rgba(255,79,0,0.1)",
                      fontSize: "10.5px",
                      fontWeight: 700,
                      letterSpacing: "0.04em",
                      color: "var(--color-accent)",
                    }}
                  >
                    {t}
                  </span>
                ))}
              </div>
            </DetailField>
          ) : null}

          {probe.rationale ? (
            <DetailField label="Classifier rationale">
              <p style={{ fontSize: "12.5px", color: "var(--color-body)", lineHeight: 1.6 }}>
                {probe.rationale}
              </p>
            </DetailField>
          ) : null}

          {probe.error_message ? (
            <DetailField label="Error">
              <pre style={{
                fontSize: "11.5px",
                color: "#B71D18",
                background: "rgba(255,86,48,0.05)",
                border: "1px solid rgba(255,86,48,0.3)",
                borderRadius: "4px",
                padding: "8px",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}>
                {probe.error_message}
              </pre>
            </DetailField>
          ) : null}

          <div className="flex items-center gap-2 pt-2">
            {probe.html_evidence_sha256 ? (
              <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "11.5px", color: "var(--color-body)", fontFamily: "monospace" }}>
                <Sparkles style={{ width: "12px", height: "12px" }} />
                HTML SHA: {probe.html_evidence_sha256.slice(0, 12)}…
              </span>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}

function DetailField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div style={{ fontSize: "10.5px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.12em", color: "var(--color-muted)", marginBottom: "6px" }}>
        {label}
      </div>
      <div>{children}</div>
    </div>
  );
}
