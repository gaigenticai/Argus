"use client";

/**
 * User-self-service feed subscriptions (P3 #3.4 — closes the audit's
 * "no dashboard surface for feed subscriptions" demo-killer).
 *
 * Each row is the current user's saved alert filter + delivery
 * channels. The page lets the analyst create new subscriptions,
 * delete their own, and dry-run a sample alert payload against the
 * filter to verify it matches before they wire a real webhook.
 */

import { useEffect, useState } from "react";
import {
  Bell,
  CheckCircle2,
  Loader2,
  Plus,
  Trash2,
  Webhook,
  Mail,
  MessageSquare,
  XCircle,
} from "lucide-react";
import {
  api,
  type FeedSubscriptionChannelEntry,
  type FeedSubscriptionRow,
} from "@/lib/api";
import { useToast } from "@/components/shared/toast";

export default function FeedSubscriptionsPage() {
  const [rows, setRows] = useState<FeedSubscriptionRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const { toast } = useToast();

  const reload = async () => {
    try {
      const list = await api.listFeedSubscriptions();
      setRows(list);
    } catch (err) {
      toast("error", `Failed to load subscriptions: ${(err as Error).message}`);
      setRows([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    reload();
  }, []);

  const onDelete = async (id: string) => {
    if (!confirm("Delete this subscription? The webhook stops firing.")) return;
    try {
      await api.deleteFeedSubscription(id);
      toast("success", "Subscription deleted");
      await reload();
    } catch (err) {
      toast("error", `Delete failed: ${(err as Error).message}`);
    }
  };

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Bell className="size-6 text-[var(--color-accent)]" aria-hidden />
          <div>
            <h1 className="text-2xl font-semibold">Feed subscriptions</h1>
            <p className="text-sm text-[var(--color-muted)]">
              Save alert filters and have new alerts pushed to your own
              webhook, email, or Slack channel.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setCreating(true)}
          className="inline-flex items-center gap-1 rounded-md bg-[var(--color-accent)] px-3 py-2 text-sm font-medium text-white hover:opacity-90"
        >
          <Plus className="size-4" aria-hidden />
          New subscription
        </button>
      </header>

      {loading ? (
        <div className="flex items-center gap-2 py-8 text-sm text-[var(--color-muted)]">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          Loading…
        </div>
      ) : rows.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[var(--color-border)] p-8 text-center text-sm text-[var(--color-muted)]">
          No subscriptions yet. Click <strong>New subscription</strong> to
          create your first webhook / email forwarding rule.
        </div>
      ) : (
        <div className="space-y-3">
          {rows.map((s) => (
            <SubscriptionCard key={s.id} sub={s} onDelete={onDelete} />
          ))}
        </div>
      )}

      {creating && (
        <CreateModal
          onCancel={() => setCreating(false)}
          onCreated={async () => {
            setCreating(false);
            toast("success", "Subscription created");
            await reload();
          }}
        />
      )}
    </div>
  );
}


function SubscriptionCard({
  sub,
  onDelete,
}: {
  sub: FeedSubscriptionRow;
  onDelete: (id: string) => void;
}) {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-base font-medium">{sub.name}</h3>
            {sub.active ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-[rgba(0,167,111,0.1)] px-2 py-0.5 text-xs text-[#007B55]">
                <CheckCircle2 className="size-3" aria-hidden />
                Active
              </span>
            ) : (
              <span className="rounded-full bg-[var(--color-surface-muted)] px-2 py-0.5 text-xs text-[var(--color-muted)]">
                Paused
              </span>
            )}
          </div>
          {sub.description && (
            <p className="mt-1 text-sm text-[var(--color-muted)]">
              {sub.description}
            </p>
          )}
        </div>
        <button
          type="button"
          onClick={() => onDelete(sub.id)}
          className="inline-flex items-center gap-1 rounded-md border border-[var(--color-border)] px-2 py-1 text-xs hover:bg-[rgba(255,86,48,0.08)] hover:text-[#B71D18]"
        >
          <Trash2 className="size-3" aria-hidden />
          Delete
        </button>
      </div>

      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <div>
          <div className="text-xs uppercase text-[var(--color-muted)]">
            Filter
          </div>
          <pre className="mt-1 max-h-32 overflow-auto rounded-md border border-[var(--color-border)] bg-[var(--color-surface-muted)] p-2 text-xs">
            {JSON.stringify(sub.filter, null, 2)}
          </pre>
        </div>
        <div>
          <div className="text-xs uppercase text-[var(--color-muted)]">
            Channels
          </div>
          <ul className="mt-1 space-y-1 text-sm">
            {sub.channels.map((c, i) => (
              <li key={i} className="flex items-center gap-2">
                <ChannelIcon type={c.type} />
                <span className="font-medium">{c.type}</span>
                <span className="text-[var(--color-muted)] truncate">
                  {c.url ?? c.address}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {sub.last_error && (
        <div className="mt-3 flex items-start gap-2 rounded-md border border-[#B71D18] bg-[rgba(255,86,48,0.1)] p-2 text-xs text-[#B71D18]">
          <XCircle className="mt-0.5 size-3" aria-hidden />
          <div>
            <strong>Last delivery error:</strong> {sub.last_error}
          </div>
        </div>
      )}
    </div>
  );
}


function ChannelIcon({ type }: { type: string }) {
  if (type === "email") return <Mail className="size-4" aria-hidden />;
  if (type === "slack")
    return <MessageSquare className="size-4" aria-hidden />;
  return <Webhook className="size-4" aria-hidden />;
}


function CreateModal({
  onCancel,
  onCreated,
}: {
  onCancel: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [filterJson, setFilterJson] = useState(
    `{\n  "severity": ["critical", "high"]\n}`,
  );
  const [channelType, setChannelType] = useState<"webhook" | "email" | "slack">(
    "webhook",
  );
  const [target, setTarget] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      let filter: Record<string, unknown>;
      try {
        filter = JSON.parse(filterJson);
      } catch {
        throw new Error("filter is not valid JSON");
      }
      const channel: FeedSubscriptionChannelEntry =
        channelType === "email"
          ? { type: "email", address: target.trim() }
          : { type: channelType, url: target.trim() };
      if (
        (channelType === "email" && !channel.address) ||
        (channelType !== "email" && !channel.url)
      ) {
        throw new Error("delivery target is required");
      }
      await api.createFeedSubscription({
        name: name.trim(),
        filter,
        channels: [channel],
        active: true,
      });
      onCreated();
    } catch (err) {
      setError((err as Error).message);
      toast("error", `Create failed: ${(err as Error).message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
    >
      <div className="w-full max-w-lg rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <h2 className="text-lg font-semibold">New feed subscription</h2>
        <div className="mt-4 space-y-3">
          <div>
            <label className="text-xs uppercase text-[var(--color-muted)]">
              Name
            </label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Critical phishing → SOC #soc"
              className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface-muted)] px-2 py-1 text-sm"
            />
          </div>
          <div>
            <label className="text-xs uppercase text-[var(--color-muted)]">
              Filter (JSON)
            </label>
            <textarea
              value={filterJson}
              onChange={(e) => setFilterJson(e.target.value)}
              rows={5}
              className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface-muted)] px-2 py-1 font-mono text-xs"
            />
            <p className="mt-1 text-xs text-[var(--color-muted)]">
              Keys: <code>severity</code>, <code>category</code>,{" "}
              <code>tags_any</code>, <code>tags_all</code>,{" "}
              <code>min_confidence</code>, <code>title_contains</code>,{" "}
              <code>title_regex</code>. Empty object matches every alert.
            </p>
          </div>
          <div className="flex gap-2">
            <select
              value={channelType}
              onChange={(e) =>
                setChannelType(
                  e.target.value as "webhook" | "email" | "slack",
                )
              }
              className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-muted)] px-2 py-1 text-sm"
            >
              <option value="webhook">Webhook</option>
              <option value="email">Email</option>
              <option value="slack">Slack</option>
            </select>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={
                channelType === "email"
                  ? "you@bank.example"
                  : "https://hooks.slack.com/…"
              }
              className="flex-1 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-muted)] px-2 py-1 text-sm"
            />
          </div>
          {error && (
            <div className="rounded-md border border-[#B71D18] bg-[rgba(255,86,48,0.1)] p-2 text-xs text-[#B71D18]">
              {error}
            </div>
          )}
        </div>
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={submitting}
            className="rounded-md border border-[var(--color-border)] px-3 py-1.5 text-sm hover:bg-[var(--color-surface-muted)]"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={submitting || !name.trim() || !target.trim()}
            className="inline-flex items-center gap-1 rounded-md bg-[var(--color-accent)] px-3 py-1.5 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
          >
            {submitting ? (
              <Loader2 className="size-3 animate-spin" aria-hidden />
            ) : null}
            Create
          </button>
        </div>
      </div>
    </div>
  );
}
