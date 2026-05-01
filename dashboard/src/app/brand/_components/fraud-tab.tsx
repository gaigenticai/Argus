"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertOctagon, ExternalLink } from "lucide-react";
import {
  api,
  type FraudFindingResponse,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  PaginationFooter,
  Section,
  Select,
  SkeletonRows,
  StatePill,
  Th,
  type StateTone,
} from "@/components/shared/page-primitives";
import { timeAgo } from "@/lib/utils";
import { useBrandContext } from "./use-brand-context";

const STATE_TONE: Record<string, StateTone> = {
  open: "neutral",
  reported_to_regulator: "warning",
  takedown_requested: "warning-strong",
  dismissed: "muted",
  confirmed: "error-strong",
};

const KIND_LABEL: Record<string, string> = {
  investment_scam: "INVESTMENT",
  crypto_giveaway: "CRYPTO",
  romance_scam: "ROMANCE",
  job_offer: "JOB",
  tech_support: "TECH SUP",
  shill_channel: "SHILL",
  other: "OTHER",
};

const CHANNEL_LABEL: Record<string, string> = {
  website: "WEB",
  telegram: "TELEGRAM",
  discord: "DISCORD",
  social: "SOCIAL",
  email: "EMAIL",
  sms: "SMS",
  other: "OTHER",
};

const PAGE_LIMIT = 50;

export function FraudTab() {
  const { orgId} = useBrandContext();
  const { toast } = useToast();
  const [rows, setRows] = useState<FraudFindingResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [channel, setChannel] = useState("all");
  const [state, setState] = useState("all");
  const [kind, setKind] = useState("all");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const { data, page } = await api.social.listFraud({
        organization_id: orgId,
        channel: channel === "all" ? undefined : channel,
        state: state === "all" ? undefined : state,
        kind: kind === "all" ? undefined : kind,
        limit: PAGE_LIMIT,
        offset,
      });
      setRows(data);
      setTotal(page.total ?? data.length);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load fraud findings",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, channel, state, kind, offset, toast]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="Channel"
          value={channel}
          options={[
            { value: "all", label: "Any channel" },
            { value: "website", label: "Website" },
            { value: "telegram", label: "Telegram" },
            { value: "discord", label: "Discord" },
            { value: "social", label: "Social" },
            { value: "email", label: "Email" },
            { value: "sms", label: "SMS" },
          ]}
          onChange={(v) => {
            setChannel(v);
            setOffset(0);
          }}
        />
        <Select
          ariaLabel="Kind"
          value={kind}
          options={[
            { value: "all", label: "Any kind" },
            { value: "crypto_giveaway", label: "Crypto giveaway" },
            { value: "investment_scam", label: "Investment scam" },
            { value: "romance_scam", label: "Romance scam" },
            { value: "job_offer", label: "Job offer" },
            { value: "tech_support", label: "Tech support" },
            { value: "shill_channel", label: "Shill channel" },
            { value: "other", label: "Other" },
          ]}
          onChange={(v) => {
            setKind(v);
            setOffset(0);
          }}
        />
        <Select
          ariaLabel="State"
          value={state}
          options={[
            { value: "all", label: "Any state" },
            { value: "open", label: "Open" },
            { value: "confirmed", label: "Confirmed" },
            { value: "reported_to_regulator", label: "Reported" },
            { value: "takedown_requested", label: "Takedown" },
            { value: "dismissed", label: "Dismissed" },
          ]}
          onChange={(v) => {
            setState(v);
            setOffset(0);
          }}
        />
      </div>

      <Section>
        {loading ? (
          <SkeletonRows rows={8} columns={6} />
        ) : rows.length === 0 ? (
          <Empty
            icon={AlertOctagon}
            title="No fraud findings match"
            description="The fraud scorer fires when scraped social, telegram, or web content exceeds the threshold for crypto-giveaway / investment-scam / shill / etc. signal."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[100px]">
                    Score
                  </Th>
                  <Th align="left">Title</Th>
                  <Th align="left" className="w-[110px]">
                    Channel
                  </Th>
                  <Th align="left" className="w-[110px]">
                    Kind
                  </Th>
                  <Th align="left">Brand & keywords</Th>
                  <Th align="left" className="w-[140px]">
                    State
                  </Th>
                  <Th align="right" className="pr-4 w-[120px]">
                    Detected
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <FraudRow key={r.id} r={r} />
                ))}
              </tbody>
            </table>
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
    </div>
  );
}

function FraudRow({ r }: { r: FraudFindingResponse }) {
  const [hovered, setHovered] = useState(false);
  const [linkHov, setLinkHov] = useState(false);
  return (
    <tr
      style={{
        height: "56px",
        borderBottom: "1px solid var(--color-border)",
        background: hovered ? "var(--color-surface)" : "transparent",
        transition: "background 0.15s",
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <td className="pl-4">
        <ScoreBar value={r.score} />
      </td>
      <td className="px-3">
        <a
          href={r.target_identifier}
          target="_blank"
          rel="noopener noreferrer nofollow"
          onMouseEnter={() => setLinkHov(true)}
          onMouseLeave={() => setLinkHov(false)}
          style={{
            fontSize: "13px",
            fontWeight: 600,
            color: linkHov ? "var(--color-accent)" : "var(--color-ink)",
            display: "inline-flex",
            alignItems: "center",
            gap: "4px",
            transition: "color 0.15s",
          }}
          className="line-clamp-1"
        >
          {r.title || r.target_identifier}
          <ExternalLink style={{ width: "12px", height: "12px", color: "var(--color-muted)", flexShrink: 0 }} />
        </a>
        {r.excerpt ? (
          <div style={{ fontSize: "11.5px", color: "var(--color-muted)", marginTop: "2px" }} className="line-clamp-1">
            {r.excerpt}
          </div>
        ) : null}
      </td>
      <td className="px-3">
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          height: "18px",
          padding: "0 6px",
          borderRadius: "4px",
          background: "var(--color-surface-muted)",
          fontSize: "10.5px",
          fontWeight: 700,
          color: "var(--color-body)",
          letterSpacing: "0.06em",
        }}>
          {CHANNEL_LABEL[r.channel] || r.channel.toUpperCase()}
        </span>
      </td>
      <td className="px-3">
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          height: "18px",
          padding: "0 6px",
          borderRadius: "4px",
          background: "rgba(255,171,0,0.1)",
          color: "#B76E00",
          fontSize: "10.5px",
          fontWeight: 700,
          letterSpacing: "0.06em",
        }}>
          {KIND_LABEL[r.kind] || r.kind.toUpperCase()}
        </span>
      </td>
      <td className="px-3">
        <div className="flex flex-wrap items-center gap-1">
          {r.matched_brand_terms.slice(0, 2).map((t) => (
            <span
              key={t}
              style={{
                display: "inline-flex",
                alignItems: "center",
                height: "16px",
                padding: "0 4px",
                borderRadius: "3px",
                background: "rgba(255,79,0,0.1)",
                color: "var(--color-accent)",
                fontSize: "9.5px",
                fontWeight: 700,
                letterSpacing: "0.04em",
              }}
            >
              {t}
            </span>
          ))}
          {r.matched_keywords.slice(0, 3).map((k) => (
            <span
              key={k}
              style={{
                display: "inline-flex",
                alignItems: "center",
                height: "16px",
                padding: "0 4px",
                borderRadius: "3px",
                background: "var(--color-surface-muted)",
                fontSize: "9.5px",
                fontFamily: "monospace",
                color: "var(--color-body)",
              }}
            >
              {k}
            </span>
          ))}
        </div>
      </td>
      <td className="px-3">
        <StatePill
          label={r.state.replace("_", " ").toUpperCase()}
          tone={STATE_TONE[r.state] || "neutral"}
        />
      </td>
      <td className="pr-4" style={{ textAlign: "right", fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(r.detected_at)}
      </td>
    </tr>
  );
}

function ScoreBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value));
  const fillColor =
    pct >= 0.7 ? "#FF5630" : pct >= 0.5 ? "#FFAB00" : "#00B8D9";
  return (
    <div className="flex items-center gap-1.5">
      <div style={{ width: "48px", height: "4px", borderRadius: "9999px", background: "var(--color-surface-muted)", overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct * 100}%`, background: fillColor }} />
      </div>
      <span style={{ fontFamily: "monospace", fontSize: "11px", color: "var(--color-body)" }}>
        {pct.toFixed(2)}
      </span>
    </div>
  );
}
