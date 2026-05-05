// Per-tool result renderers (T69).
//
// Each backend tool returns a structured result that's much more useful
// when rendered as a domain card than as a raw JSON blob. The dispatch
// is intentionally permissive — when the backend returns ``{"error": ...}``
// (failed lookup, hallucinated args), we fall back to the raw JSON so
// the analyst still sees what happened.
//
// Shape of each result is documented in the @tool decorator's
// description in src/agents/investigation_agent.py — keep in sync.

import Link from "next/link";
import { ExternalLink } from "lucide-react";

import type { ToolName } from "./tool-meta";

// -- Helpers -----------------------------------------------------------

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

function LookupAlertCard({ result }: { result: Record<string, unknown> }) {
  const id = String(result.id || "");
  const title = (result.title as string | undefined) || "(no title)";
  const summary = result.summary as string | undefined;
  const sev = result.severity as string | undefined;
  const cat = result.category as string | undefined;
  const matched = result.matched_entities as Record<string, string> | undefined;
  return (
    <div style={cardBox}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
        {sev ? <span style={monoChip}>{sev.toUpperCase()}</span> : null}
        {cat ? <span style={{ ...monoChip, background: "var(--color-surface-muted)" }}>{cat}</span> : null}
        {id ? (
          <Link href={`/alerts/${id}`} style={linkStyle}>
            <span style={{ fontFamily: "monospace", fontSize: 11 }}>{id.slice(0, 8)}…</span>
            <ExternalLink style={{ width: 11, height: 11 }} />
          </Link>
        ) : null}
      </div>
      <div style={{ fontSize: 13, color: "var(--color-ink)", fontWeight: 600, marginBottom: 4 }}>
        {title}
      </div>
      {summary ? (
        <p style={{ fontSize: 12, color: "var(--color-body)", margin: 0, marginBottom: 4 }}>
          {summary}
        </p>
      ) : null}
      {matched && Object.keys(matched).length > 0 ? (
        <ul style={{ margin: 0, padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: 2 }}>
          {Object.entries(matched).slice(0, 4).map(([k, v]) => (
            <li key={k} style={{ fontSize: 11.5, color: "var(--color-body)" }}>
              <span style={{ fontWeight: 700, color: "var(--color-ink)" }}>{k}:</span>{" "}
              {v as string}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function SearchIOCsResult({ result }: { result: unknown }) {
  // Backend returns {iocs: [...], total: int}. Be defensive — empty
  // result lists go through here too.
  const obj = (result || {}) as { iocs?: Record<string, unknown>[]; total?: number };
  const iocs = Array.isArray(obj.iocs) ? obj.iocs : [];
  if (iocs.length === 0) {
    return (
      <div style={{ ...cardBox, fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>
        No matching IOCs.
      </div>
    );
  }
  return (
    <div style={{ ...cardBox, padding: 0 }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
        <thead>
          <tr style={{ background: "var(--color-surface-muted)" }}>
            <th style={{ padding: "4px 8px", textAlign: "left", fontSize: 10, color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase" }}>
              Type
            </th>
            <th style={{ padding: "4px 8px", textAlign: "left", fontSize: 10, color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase" }}>
              Value
            </th>
            <th style={{ padding: "4px 8px", textAlign: "right", fontSize: 10, color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase" }}>
              Conf
            </th>
            <th style={{ padding: "4px 8px", textAlign: "left", fontSize: 10, color: "var(--color-muted)", fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase" }}>
              Actor
            </th>
          </tr>
        </thead>
        <tbody>
          {iocs.slice(0, 25).map((i, idx) => {
            const id = String(i.id || "");
            return (
              <tr key={id || idx} style={{ borderTop: "1px solid var(--color-surface-muted)" }}>
                <td style={{ padding: "4px 8px" }}>
                  <span style={monoChip}>{String(i.ioc_type || "—")}</span>
                </td>
                <td style={{ padding: "4px 8px", fontFamily: "monospace", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {id ? (
                    <Link href={`/iocs/${id}`} style={{ ...linkStyle, color: "var(--color-accent)" }}>
                      {String(i.value || "")}
                    </Link>
                  ) : (
                    String(i.value || "")
                  )}
                </td>
                <td style={{ padding: "4px 8px", textAlign: "right", fontFamily: "monospace", color: "var(--color-body)" }}>
                  {typeof i.confidence === "number" ? `${Math.round(i.confidence * 100)}%` : "—"}
                </td>
                <td style={{ padding: "4px 8px", color: "var(--color-body)", fontSize: 11 }}>
                  {(i.threat_actor as string | undefined) || "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {iocs.length > 25 ? (
        <div style={{ padding: "4px 8px", fontSize: 10.5, color: "var(--color-muted)", borderTop: "1px solid var(--color-border)" }}>
          Showing 25 of {iocs.length}.
        </div>
      ) : null}
    </div>
  );
}

function LookupActorCard({ result }: { result: Record<string, unknown> }) {
  const id = String(result.id || "");
  const alias = result.primary_alias as string | undefined;
  const aliases = (result.aliases as string[] | undefined) || [];
  const desc = result.description as string | undefined;
  const ttps = (result.known_ttps as string[] | undefined) || [];
  const risk = result.risk_score as number | undefined;
  return (
    <div style={cardBox}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--color-ink)" }}>
          {alias || "(unknown actor)"}
        </span>
        {typeof risk === "number" ? (
          <span style={{ ...monoChip, color: risk >= 80 ? "#B71D18" : risk >= 50 ? "#B76E00" : "var(--color-body)" }}>
            risk {risk}
          </span>
        ) : null}
        {id ? (
          <Link href={`/actors/${id}`} style={linkStyle}>
            <ExternalLink style={{ width: 11, height: 11 }} />
          </Link>
        ) : null}
      </div>
      {aliases.length > 0 ? (
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 4 }}>
          {aliases.slice(0, 6).map((a) => (
            <span key={a} style={{ ...monoChip, fontSize: 10 }}>{a}</span>
          ))}
        </div>
      ) : null}
      {desc ? (
        <p style={{ fontSize: 12, color: "var(--color-body)", margin: 0, marginBottom: 4 }}>{desc}</p>
      ) : null}
      {ttps.length > 0 ? (
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          <span style={{ fontSize: 10.5, color: "var(--color-muted)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700 }}>
            TTPs:
          </span>
          {ttps.slice(0, 8).map((t) => (
            <span key={t} style={{ ...monoChip, fontSize: 10 }}>{t}</span>
          ))}
          {ttps.length > 8 ? (
            <span style={{ fontSize: 10.5, color: "var(--color-muted)" }}>+{ttps.length - 8}</span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function RelatedAlertsList({ result }: { result: unknown }) {
  const obj = (result || {}) as { alerts?: Record<string, unknown>[] };
  const alerts = Array.isArray(obj.alerts) ? obj.alerts : [];
  if (alerts.length === 0) {
    return (
      <div style={{ ...cardBox, fontSize: 12, color: "var(--color-muted)", fontStyle: "italic" }}>
        No related alerts.
      </div>
    );
  }
  return (
    <ul style={{ ...cardBox, listStyle: "none", padding: 8, margin: 0, display: "flex", flexDirection: "column", gap: 4 }}>
      {alerts.slice(0, 10).map((a) => {
        const id = String(a.id || "");
        const title = (a.title as string | undefined) || "(no title)";
        const sev = a.severity as string | undefined;
        return (
          <li key={id} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
            {sev ? <span style={monoChip}>{sev.toUpperCase()}</span> : null}
            <Link
              href={`/alerts/${id}`}
              style={{ ...linkStyle, color: "var(--color-ink)" }}
            >
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 380 }}>
                {title}
              </span>
              <ExternalLink style={{ width: 11, height: 11, color: "var(--color-muted)" }} />
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function AssetExposureCard({ result }: { result: Record<string, unknown> }) {
  const value = result.value as string | undefined;
  const asset_type = result.asset_type as string | undefined;
  const exposures = (result.exposures as Record<string, unknown>[] | undefined) || [];
  return (
    <div style={cardBox}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
        {asset_type ? <span style={monoChip}>{asset_type}</span> : null}
        <span style={{ fontFamily: "monospace", fontSize: 12, color: "var(--color-ink)" }}>
          {value || "(no value)"}
        </span>
      </div>
      {exposures.length > 0 ? (
        <ul style={{ margin: 0, padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: 2 }}>
          {exposures.slice(0, 6).map((e, idx) => (
            <li key={idx} style={{ fontSize: 11.5, color: "var(--color-body)" }}>
              <span style={monoChip}>{String(e.kind || "exposure")}</span>{" "}
              <span>{(e.title as string | undefined) || (e.target as string | undefined) || "—"}</span>
            </li>
          ))}
          {exposures.length > 6 ? (
            <li style={{ fontSize: 10.5, color: "var(--color-muted)" }}>
              +{exposures.length - 6} more
            </li>
          ) : null}
        </ul>
      ) : (
        <div style={{ fontSize: 12, color: "var(--color-muted)" }}>No exposures recorded.</div>
      )}
    </div>
  );
}

// -- Dispatch ----------------------------------------------------------

const RENDERERS: Record<
  ToolName,
  (props: { result: any }) => React.ReactNode  // eslint-disable-line @typescript-eslint/no-explicit-any
> = {
  lookup_alert: LookupAlertCard,
  search_iocs: SearchIOCsResult,
  lookup_threat_actor: LookupActorCard,
  related_alerts: RelatedAlertsList,
  lookup_asset_exposure: AssetExposureCard,
};

/** Render a tool result with the appropriate domain card. Falls back
 *  to JSON for unknown tools or error results. */
export function ToolResult({
  tool,
  result,
}: {
  tool: string | null | undefined;
  result: unknown;
}) {
  if (result === null || result === undefined) return null;
  if (isErrorResult(result)) {
    return <ErrorBox message={result.error} />;
  }
  const Renderer = tool && (RENDERERS as Record<string, typeof RENDERERS[ToolName]>)[tool];
  if (!Renderer) {
    return <RawJSON value={result} />;
  }
  try {
    return <Renderer result={result as Record<string, unknown>} />;
  } catch {
    // Defensive — if a renderer crashes, fall back to JSON so the
    // operator can still see what came back.
    return <RawJSON value={result} />;
  }
}
