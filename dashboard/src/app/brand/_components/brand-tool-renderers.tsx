// Per-tool result renderers for the Brand Defender's 5-tool catalogue.
// Mirror of the InvestigationAgent's tool-renderers.tsx — defensive,
// falls back to JSON for unknown tools or error results.

import Link from "next/link";
import { ExternalLink } from "lucide-react";

import type { BrandToolName } from "./labels";
import { riskSignalLabel } from "./labels";

const cardBox: React.CSSProperties = {
  border: "1px solid var(--color-border)",
  borderRadius: 4,
  padding: "8px 12px",
  background: "var(--color-canvas)",
};

const monoChip: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  padding: "1px 6px",
  borderRadius: 3,
  background: "var(--color-surface-muted)",
  color: "var(--color-body)",
  fontSize: 10.5,
  fontFamily: "monospace",
  fontWeight: 700,
  letterSpacing: "0.04em",
};

const linkStyle: React.CSSProperties = {
  color: "var(--color-accent)",
  textDecoration: "none",
  display: "inline-flex",
  alignItems: "center",
  gap: 4,
};

function isErrorResult(result: unknown): result is { error: string } {
  return (
    typeof result === "object"
    && result !== null
    && typeof (result as Record<string, unknown>).error === "string"
  );
}

function RawJSON({ value }: { value: unknown }) {
  return (
    <pre
      style={{
        fontSize: 11,
        fontFamily: "monospace",
        background: "var(--color-border-strong)",
        color: "var(--color-on-dark)",
        padding: "8px 12px",
        borderRadius: 4,
        overflowX: "auto",
        maxHeight: 280,
        margin: 0,
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
      }}
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div
      role="alert"
      style={{
        ...cardBox,
        background: "rgba(255,86,48,0.07)",
        borderColor: "rgba(255,86,48,0.35)",
        color: "#B71D18",
        fontSize: 12,
        fontFamily: "monospace",
      }}
    >
      {message}
    </div>
  );
}

// -- Per-tool renderers ------------------------------------------------

function LookupSuspectCard({ result }: { result: Record<string, unknown> }) {
  const id = String(result.id || "");
  const domain = (result.domain as string | undefined) || "(no domain)";
  const matched = result.matched_term_value as string | undefined;
  const sim = result.similarity as number | undefined;
  const source = result.source as string | undefined;
  const state = result.state as string | undefined;
  const aRecords = (result.a_records as string[] | undefined) || [];
  return (
    <div style={cardBox}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
        <span style={{ fontFamily: "monospace", fontSize: 13, color: "var(--color-ink)", fontWeight: 600 }}>
          {domain}
        </span>
        {typeof sim === "number" ? (
          <span
            style={{
              ...monoChip,
              color: sim >= 0.9 ? "#B71D18" : sim >= 0.75 ? "#B76E00" : "var(--color-body)",
            }}
          >
            {Math.round(sim * 100)}%
          </span>
        ) : null}
        {state ? <span style={monoChip}>{state}</span> : null}
        {source ? <span style={monoChip}>{source}</span> : null}
      </div>
      {matched ? (
        <div style={{ fontSize: 11.5, color: "var(--color-body)" }}>
          matches{" "}
          <span style={{ fontFamily: "monospace", color: "var(--color-ink)" }}>
            {matched}
          </span>
        </div>
      ) : null}
      {aRecords.length > 0 ? (
        <div style={{ marginTop: 4, fontSize: 11, color: "var(--color-muted)", fontFamily: "monospace" }}>
          A: {aRecords.slice(0, 3).join(", ")}
          {aRecords.length > 3 ? ` (+${aRecords.length - 3})` : ""}
        </div>
      ) : null}
      {id ? (
        <div style={{ marginTop: 4 }}>
          <Link
            href={`/brand?tab=suspects&id=${id}`}
            style={{ ...linkStyle, fontSize: 11.5 }}
          >
            Open suspect
            <ExternalLink style={{ width: 11, height: 11 }} />
          </Link>
        </div>
      ) : null}
    </div>
  );
}

function LookupLiveProbeCard({ result }: { result: Record<string, unknown> }) {
  const verdict = (result.verdict as string | undefined) || "unknown";
  const url = result.url as string | undefined;
  const finalUrl = result.final_url as string | undefined;
  const title = result.title as string | undefined;
  const conf = result.confidence as number | undefined;
  const signals = (result.signals as string[] | undefined) || [];
  const verdictTone =
    verdict === "phishing" ? "#B71D18"
      : verdict === "suspicious" ? "#B76E00"
      : verdict === "benign" ? "#007B55"
      : "var(--color-muted)";
  return (
    <div style={cardBox}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
        <span style={{ ...monoChip, color: verdictTone }}>{verdict.toUpperCase()}</span>
        {typeof conf === "number" ? (
          <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--color-body)" }}>
            {Math.round(conf * 100)}%
          </span>
        ) : null}
      </div>
      {title ? (
        <div style={{ fontSize: 12.5, color: "var(--color-ink)", marginBottom: 4 }}>{title}</div>
      ) : null}
      {(url || finalUrl) ? (
        <div style={{ fontFamily: "monospace", fontSize: 11, color: "var(--color-muted)", wordBreak: "break-all" }}>
          {finalUrl || url}
        </div>
      ) : null}
      {signals.length > 0 ? (
        <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 4 }}>
          {signals.slice(0, 6).map((s) => (
            <span key={s} style={monoChip} title={riskSignalLabel(s)}>
              {s}
            </span>
          ))}
          {signals.length > 6 ? (
            <span style={{ fontSize: 10.5, color: "var(--color-muted)" }}>
              +{signals.length - 6}
            </span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function LookupLogoMatchesList({ result }: { result: unknown }) {
  const obj = (result || {}) as { matches?: Record<string, unknown>[] };
  const matches = Array.isArray(obj.matches) ? obj.matches : [];
  if (matches.length === 0) {
    return (
      <div style={{ ...cardBox, fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>
        No logo matches.
      </div>
    );
  }
  return (
    <ul style={{ ...cardBox, listStyle: "none", margin: 0, padding: 8, display: "flex", flexDirection: "column", gap: 4 }}>
      {matches.slice(0, 8).map((m, idx) => {
        const sim = m.similarity as number | undefined;
        const url = m.url as string | undefined;
        const verdict = m.verdict as string | undefined;
        return (
          <li key={idx} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11.5 }}>
            {typeof sim === "number" ? (
              <span style={{ ...monoChip, color: sim >= 0.85 ? "#B71D18" : "var(--color-body)" }}>
                {Math.round(sim * 100)}%
              </span>
            ) : null}
            {verdict ? <span style={monoChip}>{verdict}</span> : null}
            <span style={{ fontFamily: "monospace", color: "var(--color-body)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
              {url || "—"}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function CheckSubsidiaryAllowlistCard({ result }: { result: Record<string, unknown> }) {
  const matched = Boolean(result.matched);
  const pattern = result.pattern as string | undefined;
  const reason = result.reason as string | undefined;
  return (
    <div
      style={{
        ...cardBox,
        background: matched ? "rgba(0,167,111,0.06)" : "var(--color-canvas)",
        borderColor: matched ? "rgba(0,167,111,0.35)" : "var(--color-border)",
      }}
    >
      <div style={{ fontSize: 12.5, fontWeight: 700, color: matched ? "#007B55" : "var(--color-body)", marginBottom: 4 }}>
        {matched ? "Allowlisted subsidiary" : "Not in allowlist"}
      </div>
      {matched && pattern ? (
        <div style={{ fontSize: 11.5, fontFamily: "monospace", color: "var(--color-ink)" }}>
          pattern: {pattern}
        </div>
      ) : null}
      {matched && reason ? (
        <div style={{ fontSize: 11.5, color: "var(--color-body)", marginTop: 2 }}>
          {reason}
        </div>
      ) : null}
    </div>
  );
}

function EstimateAgeCard({ result }: { result: Record<string, unknown> }) {
  const ageDays = result.age_days as number | undefined;
  const registeredAt = result.registered_at as string | undefined;
  const fresh = typeof ageDays === "number" && ageDays < 30;
  return (
    <div style={cardBox}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
          {typeof ageDays === "number" ? `${ageDays} day${ageDays === 1 ? "" : "s"} old` : "age unknown"}
        </span>
        {fresh ? (
          <span style={{ ...monoChip, color: "#B71D18" }}>FRESH</span>
        ) : null}
      </div>
      {registeredAt ? (
        <div style={{ fontSize: 11, color: "var(--color-muted)", fontFamily: "monospace", marginTop: 2 }}>
          registered: {registeredAt}
        </div>
      ) : null}
    </div>
  );
}

// -- Dispatch ----------------------------------------------------------

const RENDERERS: Record<
  BrandToolName,
  (props: { result: any }) => React.ReactNode  // eslint-disable-line @typescript-eslint/no-explicit-any
> = {
  lookup_suspect: LookupSuspectCard,
  lookup_live_probe: LookupLiveProbeCard,
  lookup_logo_matches: LookupLogoMatchesList,
  check_subsidiary_allowlist: CheckSubsidiaryAllowlistCard,
  estimate_age: EstimateAgeCard,
};

export function BrandToolResult({
  tool,
  result,
}: {
  tool: string | null | undefined;
  result: unknown;
}) {
  if (result === null || result === undefined) return null;
  if (isErrorResult(result)) return <ErrorBox message={result.error} />;
  const Renderer = tool && (RENDERERS as Record<string, typeof RENDERERS[BrandToolName]>)[tool];
  if (!Renderer) return <RawJSON value={result} />;
  try {
    return <Renderer result={result as Record<string, unknown>} />;
  } catch {
    return <RawJSON value={result} />;
  }
}
