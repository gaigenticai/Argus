"use client";

import { useCallback, useEffect, useState } from "react";
import { Apple, ExternalLink, Smartphone, Star } from "lucide-react";
import {
  api,
  type MobileAppFindingResponse,
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
  takedown_requested: "warning",
  dismissed: "muted",
  cleared: "success",
  confirmed: "error-strong",
};

const PAGE_LIMIT = 50;

export function MobileAppsTab() {
  const { orgId} = useBrandContext();
  const { toast } = useToast();
  const [rows, setRows] = useState<MobileAppFindingResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [store, setStore] = useState<"all" | "apple" | "google_play">("all");
  const [state, setState] = useState<string>("all");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!orgId) return;
    setLoading(true);
    try {
      const { data, page } = await api.social.listMobileApps({
        organization_id: orgId,
        store: store === "all" ? undefined : store,
        state: state === "all" ? undefined : state,
        limit: PAGE_LIMIT,
        offset,
      });
      setRows(data);
      setTotal(page.total ?? data.length);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load mobile apps",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, store, state, offset, toast]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <Select
          ariaLabel="Store"
          value={store}
          options={[
            { value: "all", label: "Both stores" },
            { value: "google_play", label: "Google Play" },
            { value: "apple", label: "Apple App Store" },
          ]}
          onChange={(v) => {
            setStore(v as typeof store);
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
            { value: "takedown_requested", label: "Takedown requested" },
            { value: "dismissed", label: "Dismissed" },
            { value: "cleared", label: "Cleared" },
          ]}
          onChange={(v) => {
            setState(v);
            setOffset(0);
          }}
        />
        <p style={{ fontSize: "12px", color: "var(--color-muted)", marginLeft: "auto", fontFamily: "monospace" }}>
          {total} app{total === 1 ? "" : "s"}
        </p>
      </div>

      <Section>
        {loading ? (
          <SkeletonRows rows={6} columns={6} />
        ) : rows.length === 0 ? (
          <Empty
            icon={Smartphone}
            title="No mobile apps match"
            description="The mobile-app monitor scans Google Play (google-play-scraper) and Apple App Store (iTunes Search API) every 6 hours against the org's brand-NAME terms. Findings land here."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                  <Th align="left" className="pl-4 w-[80px]">
                    Store
                  </Th>
                  <Th align="left">Title</Th>
                  <Th align="left">Publisher</Th>
                  <Th align="left" className="w-[80px]">
                    Rating
                  </Th>
                  <Th align="left" className="w-[120px]">
                    Installs
                  </Th>
                  <Th align="left" className="w-[120px]">
                    Match
                  </Th>
                  <Th align="left" className="w-[140px]">
                    State
                  </Th>
                  <Th align="right" className="pr-4 w-[120px]">
                    Updated
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <AppRow key={r.id} r={r} />
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

function AppRow({ r }: { r: MobileAppFindingResponse }) {
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
        <StoreChip store={r.store} />
      </td>
      <td className="px-3">
        {r.url ? (
          <a
            href={r.url}
            target="_blank"
            rel="noopener noreferrer nofollow"
            onMouseEnter={() => setLinkHov(true)}
            onMouseLeave={() => setLinkHov(false)}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
              fontSize: "13px",
              fontWeight: 600,
              color: linkHov ? "var(--color-accent)" : "var(--color-ink)",
              transition: "color 0.15s",
            }}
          >
            {r.title}
            <ExternalLink style={{ width: "12px", height: "12px", color: "var(--color-muted)" }} />
          </a>
        ) : (
          <span style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-ink)" }}>
            {r.title}
          </span>
        )}
        <div style={{ fontFamily: "monospace", fontSize: "10.5px", color: "var(--color-muted)", marginTop: "2px" }}>
          {r.app_id}
        </div>
      </td>
      <td className="px-3" style={{ fontSize: "12.5px", color: "var(--color-body)" }}>
        <div className="flex items-center gap-1.5">
          <span>
            {r.publisher || (
              <span style={{ color: "var(--color-muted)", fontStyle: "italic" }}>unknown</span>
            )}
          </span>
          {r.is_official_publisher ? (
            <span style={{
              display: "inline-flex",
              alignItems: "center",
              height: "16px",
              padding: "0 4px",
              borderRadius: "3px",
              background: "rgba(0,167,111,0.1)",
              color: "#007B55",
              fontSize: "9.5px",
              fontWeight: 700,
              letterSpacing: "0.06em",
            }}>
              OFFICIAL
            </span>
          ) : null}
        </div>
      </td>
      <td className="px-3">
        {r.rating !== null ? (
          <span className="inline-flex items-center gap-1" style={{ fontFamily: "monospace", fontSize: "12px", color: "var(--color-body)" }}>
            <Star style={{ width: "12px", height: "12px", color: "#FFAB00" }} />
            {r.rating.toFixed(1)}
          </span>
        ) : (
          <span style={{ fontSize: "11.5px", color: "var(--color-muted)" }}>—</span>
        )}
      </td>
      <td className="px-3" style={{ fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-body)" }}>
        {r.install_estimate || "—"}
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
          fontFamily: "monospace",
          color: "var(--color-body)",
        }}>
          {r.matched_term}
        </span>
      </td>
      <td className="px-3">
        <StatePill
          label={r.state.replace("_", " ").toUpperCase()}
          tone={STATE_TONE[r.state] || "neutral"}
        />
      </td>
      <td className="pr-4" style={{ textAlign: "right", fontFamily: "monospace", fontSize: "11.5px", color: "var(--color-muted)" }}>
        {timeAgo(r.updated_at)}
      </td>
    </tr>
  );
}

function StoreChip({ store }: { store: string }) {
  if (store === "apple") {
    return (
      <span style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        height: "20px",
        padding: "0 6px",
        borderRadius: "4px",
        border: "1px solid var(--color-border)",
        fontSize: "10.5px",
        fontWeight: 700,
        color: "var(--color-ink)",
        letterSpacing: "0.06em",
      }}>
        <Apple style={{ width: "12px", height: "12px" }} />
        APPLE
      </span>
    );
  }
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: "4px",
      height: "20px",
      padding: "0 6px",
      borderRadius: "4px",
      border: "1px solid rgba(0,187,217,0.4)",
      background: "rgba(0,187,217,0.1)",
      fontSize: "10.5px",
      fontWeight: 700,
      color: "#007B8A",
      letterSpacing: "0.06em",
    }}>
      G-PLAY
    </span>
  );
}
