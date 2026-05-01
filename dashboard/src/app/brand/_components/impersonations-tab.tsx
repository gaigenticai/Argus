"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Disc,
  ExternalLink,
  Facebook,
  Instagram,
  Linkedin,
  MessageCircle,
  UserX,
  Youtube,
} from "lucide-react";
import {
  api,
  type ImpersonationFindingResponse,
  type ImpersonationKindValue,
  type ImpersonationStateValue,
  type SocialPlatformValue,
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

const PLATFORMS: Array<{
  id: SocialPlatformValue;
  label: string;
  icon: React.ElementType;
}> = [
  { id: "twitter", label: "X", icon: Disc },
  { id: "linkedin", label: "LinkedIn", icon: Linkedin },
  { id: "instagram", label: "Instagram", icon: Instagram },
  { id: "tiktok", label: "TikTok", icon: Disc },
  { id: "facebook", label: "Facebook", icon: Facebook },
  { id: "youtube", label: "YouTube", icon: Youtube },
  { id: "telegram", label: "Telegram", icon: MessageCircle },
  { id: "discord", label: "Discord", icon: Disc },
  { id: "reddit", label: "Reddit", icon: Disc },
  { id: "mastodon", label: "Mastodon", icon: Disc },
  { id: "bluesky", label: "Bluesky", icon: Disc },
];

const STATE_TONE: Record<ImpersonationStateValue, StateTone> = {
  open: "neutral",
  confirmed: "error-strong",
  takedown_requested: "warning",
  dismissed: "muted",
  cleared: "success",
};

const KIND_LABEL: Record<ImpersonationKindValue, string> = {
  executive: "EXEC",
  brand_account: "BRAND",
  product: "PRODUCT",
};

const PAGE_LIMIT = 50;

export function ImpersonationsTab() {
  const { orgId} = useBrandContext();
  const { toast } = useToast();
  const [rows, setRows] = useState<ImpersonationFindingResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [platform, setPlatform] = useState<SocialPlatformValue | "all">("all");
  const [state, setState] = useState<ImpersonationStateValue | "all">("all");
  const [kind, setKind] = useState<ImpersonationKindValue | "all">("all");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const { data, page } = await api.social.listImpersonations({
        organization_id: orgId,
        platform: platform === "all" ? undefined : platform,
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
        e instanceof Error ? e.message : "Failed to load impersonations",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, platform, state, kind, offset, toast]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-4">
      {/* Platform pills */}
      <div className="flex items-center gap-1 flex-wrap">
        <PlatformPill
          active={platform === "all"}
          label="All"
          onClick={() => {
            setPlatform("all");
            setOffset(0);
          }}
        />
        {PLATFORMS.map((p) => (
          <PlatformPill
            key={p.id}
            active={platform === p.id}
            label={p.label}
            icon={p.icon}
            onClick={() => {
              setPlatform(p.id);
              setOffset(0);
            }}
          />
        ))}
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="State"
          value={state}
          options={[
            { value: "all", label: "Any state" },
            { value: "open", label: "Open" },
            { value: "confirmed", label: "Confirmed" },
            { value: "takedown_requested", label: "Takedown requested" },
            { value: "dismissed", label: "Dismissed" },
            { value: "cleared", label: "Cleared" },
          ]}
          onChange={(v) => {
            setState(v as ImpersonationStateValue | "all");
            setOffset(0);
          }}
        />
        <Select
          ariaLabel="Kind"
          value={kind}
          options={[
            { value: "all", label: "Any kind" },
            { value: "executive", label: "Executive" },
            { value: "brand_account", label: "Brand account" },
            { value: "product", label: "Product" },
          ]}
          onChange={(v) => {
            setKind(v as ImpersonationKindValue | "all");
            setOffset(0);
          }}
        />
      </div>

      <Section>
        {loading ? (
          <SkeletonRows rows={8} columns={6} />
        ) : rows.length === 0 ? (
          <Empty
            icon={UserX}
            title="No impersonations match"
            description="Once social monitors (Telegram, Instagram, TikTok, Twitter, LinkedIn) score a candidate handle above the threshold, it lands here."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[100px]">
                    Score
                  </Th>
                  <Th align="left">Handle</Th>
                  <Th align="left">Display name</Th>
                  <Th align="left" className="w-[110px]">
                    Platform
                  </Th>
                  <Th align="left" className="w-[80px]">
                    Kind
                  </Th>
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
                  <ImpersonationRow key={r.id} r={r} />
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

function ImpersonationRow({ r }: { r: ImpersonationFindingResponse }) {
  const [hovered, setHovered] = useState(false);
  const [linkHov, setLinkHov] = useState(false);
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
        <ScoreBar value={r.aggregate_score} />
      </td>
      <td className="px-3">
        {r.candidate_url ? (
          <a
            href={r.candidate_url}
            target="_blank"
            rel="noopener noreferrer nofollow"
            onMouseEnter={() => setLinkHov(true)}
            onMouseLeave={() => setLinkHov(false)}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
              fontFamily: "monospace",
              fontSize: "12.5px",
              color: linkHov ? "var(--color-accent)" : "var(--color-ink)",
              transition: "color 0.15s",
            }}
          >
            @{r.candidate_handle}
            <ExternalLink style={{ width: "12px", height: "12px", color: "var(--color-muted)" }} />
          </a>
        ) : (
          <span style={{ fontFamily: "monospace", fontSize: "12.5px", color: "var(--color-ink)" }}>
            @{r.candidate_handle}
          </span>
        )}
      </td>
      <td className="px-3" style={{ fontSize: "12.5px", color: "var(--color-body)" }}>
        {r.candidate_display_name || (
          <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>none</span>
        )}
      </td>
      <td className="px-3">
        <PlatformChip platform={r.platform} />
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
          {KIND_LABEL[r.kind]}
        </span>
      </td>
      <td className="px-3">
        <StatePill
          label={r.state.replace("_", " ").toUpperCase()}
          tone={STATE_TONE[r.state]}
        />
      </td>
      <td className="pr-4" style={{ textAlign: "right", fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(r.detected_at)}
      </td>
    </tr>
  );
}

function PlatformPill({
  active,
  label,
  icon: Icon,
  onClick,
}: {
  active: boolean;
  label: string;
  icon?: React.ElementType;
  onClick: () => void;
}) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        height: "32px",
        padding: "0 12px",
        borderRadius: "4px",
        fontSize: "12px",
        fontWeight: 700,
        border: active
          ? "1px solid var(--color-border-strong)"
          : hov
          ? "1px solid var(--color-border-strong)"
          : "1px solid var(--color-border)",
        background: active ? "var(--color-border-strong)" : "var(--color-canvas)",
        color: active ? "var(--color-on-dark)" : "var(--color-body)",
        cursor: "pointer",
        transition: "all 0.15s",
      }}
    >
      {Icon ? <Icon style={{ width: "14px", height: "14px" }} /> : null}
      {label}
    </button>
  );
}

function PlatformChip({ platform }: { platform: string }) {
  const p = PLATFORMS.find((x) => x.id === platform);
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: "4px",
      height: "18px",
      padding: "0 6px",
      borderRadius: "4px",
      background: "var(--color-surface-muted)",
      fontSize: "10.5px",
      fontWeight: 700,
      color: "var(--color-body)",
      letterSpacing: "0.06em",
    }}>
      {p?.label || platform.toUpperCase()}
    </span>
  );
}

function ScoreBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value));
  const fillColor =
    pct >= 0.9 ? "#FF5630" : pct >= 0.75 ? "#FFAB00" : "#00B8D9";
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
