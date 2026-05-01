"use client";

import { useCallback, useEffect, useState } from "react";
import {
  ExternalLink,
  Newspaper,
  Plus,
  Rss,
} from "lucide-react";
import {
  api,
  type NewsArticleResponse,
  type NewsFeedResponse,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import {
  Empty,
  Field,
  ModalFooter,
  ModalShell,
  PageHeader,
  RefreshButton,
  Section,
  SearchInput,
  SkeletonRows,
  StatePill,
  type StateTone,
} from "@/components/shared/page-primitives";
import { formatDate, timeAgo } from "@/lib/utils";

const STATUS_TONE: Record<string, StateTone> = {
  ok: "success",
  parse_error: "error-strong",
  fetch_error: "error-strong",
  empty: "muted",
};

export default function NewsPage() {
  const { toast } = useToast();
  const [feeds, setFeeds] = useState<NewsFeedResponse[]>([]);
  const [articles, setArticles] = useState<NewsArticleResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [feedFilter, setFeedFilter] = useState<string | null>(null);
  const [showAddFeed, setShowAddFeed] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [f, a] = await Promise.all([
        api.news.listFeeds(),
        api.news.listArticles({
          feed_id: feedFilter || undefined,
          q: search || undefined,
          limit: 200,
        }),
      ]);
      setFeeds(f);
      setArticles(a);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to load news",
      );
    } finally {
      setLoading(false);
    }
  }, [feedFilter, search, toast]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={{ icon: Newspaper, label: "Intelligence" }}
        title="News"
        description="Aggregated cybersecurity news pulled from RSS / Atom / JSON feeds. Each article auto-scores for relevance against the org's brand terms, tech stack, and active CVE references."
        actions={
          <>
            <RefreshButton onClick={load} refreshing={loading} />
            <button
              onClick={() => setShowAddFeed(true)}
              className="inline-flex items-center gap-2 h-10 px-4 text-[13px] font-bold"
              style={{ borderRadius: "4px", border: "1px solid var(--color-accent)", background: "var(--color-accent)", color: "var(--color-on-dark)" }}
            >
              <Plus className="w-4 h-4" />
              Add feed
            </button>
          </>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
        {/* Feed sidebar */}
        <Section className="lg:col-span-1">
          <div className="px-4 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <h3 className="text-[12px] font-bold uppercase tracking-[0.1em]" style={{ color: "var(--color-body)" }}>
              Feeds
            </h3>
          </div>
          <ul className="max-h-[calc(100vh-360px)] overflow-y-auto">
            <li style={{ borderBottom: "1px solid var(--color-border)" }}>
              <button
                onClick={() => setFeedFilter(null)}
                className="w-full px-4 py-2.5 text-left transition-colors"
                style={{ background: feedFilter === null ? "var(--color-surface-muted)" : "transparent" }}
                onMouseEnter={e => { if (feedFilter !== null) e.currentTarget.style.background = "var(--color-surface)"; }}
                onMouseLeave={e => { if (feedFilter !== null) e.currentTarget.style.background = "transparent"; }}
              >
                <div className="text-[13px] font-bold" style={{ color: "var(--color-ink)" }}>
                  All feeds
                </div>
                <div className="text-[11px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
                  {feeds.length} configured
                </div>
              </button>
            </li>
            {feeds.map((f) => (
              <li key={f.id} style={{ borderBottom: "1px solid var(--color-border)" }}>
                <button
                  onClick={() => setFeedFilter(f.id)}
                  className="w-full px-4 py-2.5 text-left transition-colors"
                  style={{ background: feedFilter === f.id ? "var(--color-surface-muted)" : "transparent" }}
                  onMouseEnter={e => { if (feedFilter !== f.id) e.currentTarget.style.background = "var(--color-surface)"; }}
                  onMouseLeave={e => { if (feedFilter !== f.id) e.currentTarget.style.background = "transparent"; }}
                >
                  <div className="flex items-center justify-between gap-2 mb-0.5">
                    <span className="text-[13px] font-semibold truncate" style={{ color: "var(--color-ink)" }}>
                      {f.name}
                    </span>
                    {f.last_status ? (
                      <StatePill
                        label={f.last_status}
                        tone={STATUS_TONE[f.last_status] || "neutral"}
                      />
                    ) : null}
                  </div>
                  <div className="text-[11px] font-mono tabular-nums truncate" style={{ color: "var(--color-muted)" }}>
                    {f.kind.toUpperCase()} ·{" "}
                    {f.last_fetched_at ? timeAgo(f.last_fetched_at) : "never polled"}
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </Section>

        {/* Articles */}
        <Section className="lg:col-span-3">
          <div className="px-4 py-3 flex items-center gap-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
            <SearchInput
              value={search}
              onChange={setSearch}
              placeholder="Search article title…"
              shortcut=""
            />
            <p className="ml-auto text-[12px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
              {articles.length} article{articles.length === 1 ? "" : "s"}
            </p>
          </div>
          {loading ? (
            <SkeletonRows rows={8} columns={4} />
          ) : articles.length === 0 ? (
            <Empty
              icon={Rss}
              title="No articles yet"
              description="Add a feed to begin pulling vendor advisories, CVE write-ups, threat-research blog posts. Articles are deduplicated by URL hash and auto-scored for relevance."
            />
          ) : (
            <ul>
              {articles.map((a) => (
                <li key={a.id} className="px-5 py-3" style={{ borderBottom: "1px solid var(--color-border)" }}>
                  <a
                    href={a.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    dir="auto"
                    className="text-[13.5px] font-semibold line-clamp-1 inline-flex items-center gap-1 transition-colors"
                    style={{ color: "var(--color-ink)" }}
                    onMouseEnter={e => (e.currentTarget.style.color = "var(--color-accent)")}
                    onMouseLeave={e => (e.currentTarget.style.color = "var(--color-ink)")}
                  >
                    {a.title}
                    <ExternalLink className="w-3 h-3 shrink-0" style={{ color: "var(--color-muted)" }} />
                  </a>
                  {a.summary ? (
                    <p dir="auto" className="text-[12px] mt-0.5 line-clamp-2" style={{ color: "var(--color-body)" }}>
                      {a.summary}
                    </p>
                  ) : null}
                  <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                    {a.author ? (
                      <span className="text-[11px] font-semibold" style={{ color: "var(--color-muted)" }}>
                        {a.author}
                      </span>
                    ) : null}
                    <span className="text-[11px] font-mono tabular-nums" style={{ color: "var(--color-muted)" }}>
                      {a.published_at
                        ? formatDate(a.published_at)
                        : timeAgo(a.fetched_at)}
                    </span>
                    {a.cve_ids.slice(0, 3).map((c) => (
                      <span
                        key={c}
                        className="inline-flex items-center h-[16px] px-1 font-mono tabular-nums tracking-wide text-[10px]"
                        style={{ borderRadius: "4px", border: "1px solid rgba(255,86,48,0.3)", background: "rgba(255,86,48,0.05)", color: "#B71D18" }}
                      >
                        {c}
                      </span>
                    ))}
                    {a.tags.slice(0, 3).map((t) => (
                      <span
                        key={t}
                        className="inline-flex items-center h-[16px] px-1 text-[10px] font-bold"
                        style={{ borderRadius: "4px", background: "var(--color-surface-muted)", color: "var(--color-body)" }}
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>

      {showAddFeed && (
        <AddFeedModal
          onClose={() => setShowAddFeed(false)}
          onCreated={() => {
            setShowAddFeed(false);
            load();
          }}
        />
      )}
    </div>
  );
}

function AddFeedModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [kind, setKind] = useState<"rss" | "atom" | "json_feed">("rss");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!name.trim() || !url.trim() || busy) return;
    setBusy(true);
    try {
      await api.news.createFeed({
        name: name.trim(),
        url: url.trim(),
        kind,
      });
      toast("success", `Feed "${name.trim()}" added`);
      onCreated();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed");
    } finally {
      setBusy(false);
    }
  };
  const inputStyle: React.CSSProperties = { borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-ink)", outline: "none" };
  return (
    <ModalShell title="Add news feed" onClose={onClose}>
      <div className="p-6 space-y-5">
        <Field label="Name" required>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full h-10 px-3 text-[13px]"
            style={inputStyle}
            placeholder="MSRC Security Updates"
            autoFocus
          />
        </Field>
        <Field label="URL" required>
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="w-full h-10 px-3 text-[13px] font-mono"
            style={inputStyle}
            placeholder="https://api.msrc.microsoft.com/update-guide/rss"
          />
        </Field>
        <Field label="Kind" required>
          <div className="grid grid-cols-3 gap-1.5">
            {(["rss", "atom", "json_feed"] as const).map((k) => {
              const active = kind === k;
              return (
                <button
                  key={k}
                  onClick={() => setKind(k)}
                  className="h-10 flex items-center justify-center text-[11.5px] font-bold tracking-[0.06em] transition-all"
                  style={active
                    ? { borderRadius: "4px", border: "1px solid var(--color-ink)", background: "var(--color-canvas)", color: "var(--color-ink)", boxShadow: "0 0 0 2px rgba(32,21,21,0.08)" }
                    : { borderRadius: "4px", border: "1px solid var(--color-border)", background: "var(--color-canvas)", color: "var(--color-body)" }
                  }
                >
                  {k.toUpperCase()}
                </button>
              );
            })}
          </div>
        </Field>
      </div>
      <ModalFooter
        onCancel={onClose}
        onSubmit={submit}
        submitLabel={busy ? "Adding…" : "Add feed"}
        disabled={!name.trim() || !url.trim() || busy}
      />
    </ModalShell>
  );
}
