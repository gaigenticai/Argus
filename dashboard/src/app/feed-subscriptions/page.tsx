"use client";

/**
 * User-self-service feed subscriptions (P3 #3.4).
 */

import { useEffect, useState } from "react";
import {
  Bell,
  Plus,
  Trash2,
  Webhook,
  Mail,
  MessageSquare,
  XCircle,
  CheckCircle2,
} from "lucide-react";
import {
  api,
  type FeedSubscriptionChannelEntry,
  type FeedSubscriptionRow,
} from "@/lib/api";
import {
  Empty,
  PageHeader,
  Section,
  SkeletonRows,
} from "@/components/shared/page-primitives";
import { useToast } from "@/components/shared/toast";


export default function FeedSubscriptionsPage() {
  const [rows, setRows] = useState<FeedSubscriptionRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const { toast } = useToast();

  const reload = async () => {
    setLoading(true);
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
      <PageHeader
        eyebrow={{ icon: Bell, label: "Self-service feed" }}
        title="Feed subscriptions"
        description="Save alert filters and have new alerts pushed to your own webhook, email, or Slack channel. One subscription = one filter + one delivery channel."
        actions={
          <button
            type="button"
            onClick={() => setCreating(true)}
            className="inline-flex items-center gap-1.5 text-[13px] font-medium px-3 py-1.5"
            style={{
              background: "var(--color-accent)",
              color: "white",
              border: "1px solid var(--color-accent)",
              borderRadius: "5px",
            }}
          >
            <Plus className="w-3.5 h-3.5" aria-hidden />
            New subscription
          </button>
        }
      />

      <Section>
        {loading ? (
          <SkeletonRows rows={3} columns={3} />
        ) : rows.length === 0 ? (
          <Empty
            icon={Bell}
            title="No subscriptions yet"
            description="Create your first webhook / email forwarding rule and start receiving filtered alerts where you actually work — Slack, email, or a custom HTTP endpoint."
            action={
              <button
                type="button"
                onClick={() => setCreating(true)}
                className="inline-flex items-center gap-1.5 text-[13px] font-medium px-3 py-1.5"
                style={{
                  background: "var(--color-accent)",
                  color: "white",
                  border: "1px solid var(--color-accent)",
                  borderRadius: "5px",
                }}
              >
                <Plus className="w-3.5 h-3.5" aria-hidden />
                New subscription
              </button>
            }
          />
        ) : (
          <div>
            {rows.map((s, i) => (
              <SubscriptionRow
                key={s.id}
                sub={s}
                onDelete={onDelete}
                first={i === 0}
              />
            ))}
          </div>
        )}
      </Section>

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


function SubscriptionRow({
  sub,
  onDelete,
  first,
}: {
  sub: FeedSubscriptionRow;
  onDelete: (id: string) => void;
  first: boolean;
}) {
  return (
    <div
      className="px-5 py-4"
      style={{ borderTop: first ? "none" : "1px solid var(--color-border)" }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <h3
              className="text-[14px] font-semibold leading-tight"
              style={{ color: "var(--color-ink)" }}
            >
              {sub.name}
            </h3>
            <ActivePill active={sub.active} />
          </div>
          {sub.description && (
            <p
              className="text-[12px] mt-1"
              style={{ color: "var(--color-muted)" }}
            >
              {sub.description}
            </p>
          )}
        </div>
        <button
          type="button"
          onClick={() => onDelete(sub.id)}
          className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-1 transition-colors"
          style={{
            border: "1px solid var(--color-border)",
            borderRadius: "5px",
            color: "var(--color-error-dark)",
            background: "var(--color-canvas)",
          }}
        >
          <Trash2 className="w-3 h-3" aria-hidden />
          Delete
        </button>
      </div>

      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <div>
          <div
            className="text-[10px] uppercase tracking-[0.8px] font-semibold mb-1"
            style={{ color: "var(--color-muted)" }}
          >
            Filter
          </div>
          <pre
            className="text-[11px] font-mono px-3 py-2 max-h-32 overflow-auto"
            style={{
              border: "1px solid var(--color-border)",
              background: "var(--color-surface-muted)",
              borderRadius: "5px",
              color: "var(--color-ink)",
            }}
          >
            {JSON.stringify(sub.filter, null, 2)}
          </pre>
        </div>
        <div>
          <div
            className="text-[10px] uppercase tracking-[0.8px] font-semibold mb-1"
            style={{ color: "var(--color-muted)" }}
          >
            Channels
          </div>
          <ul className="space-y-1.5">
            {sub.channels.map((c, i) => (
              <li
                key={i}
                className="flex items-center gap-2 text-[12px] px-2 py-1.5"
                style={{
                  border: "1px solid var(--color-border)",
                  borderRadius: "5px",
                  background: "var(--color-canvas)",
                }}
              >
                <ChannelIcon type={c.type} />
                <span
                  className="font-semibold"
                  style={{ color: "var(--color-ink)" }}
                >
                  {c.type}
                </span>
                <span
                  className="font-mono truncate"
                  style={{ color: "var(--color-muted)" }}
                  title={c.url ?? c.address}
                >
                  {c.url ?? c.address}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {sub.last_error && (
        <div
          className="mt-3 flex items-start gap-2 px-3 py-2 text-[11px]"
          style={{
            border: "1px solid rgba(239,68,68,0.3)",
            background: "rgba(239,68,68,0.06)",
            borderRadius: "5px",
            color: "var(--color-error-dark)",
          }}
        >
          <XCircle className="w-3 h-3 mt-0.5 shrink-0" aria-hidden />
          <div>
            <strong>Last delivery error:</strong> {sub.last_error}
          </div>
        </div>
      )}
    </div>
  );
}


function ActivePill({ active }: { active: boolean }) {
  if (active) {
    return (
      <span
        className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5"
        style={{
          background: "rgba(16,185,129,0.08)",
          color: "var(--color-success-dark)",
          border: "1px solid rgba(16,185,129,0.25)",
          borderRadius: "999px",
        }}
      >
        <CheckCircle2 className="w-2.5 h-2.5" aria-hidden />
        Active
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5"
      style={{
        background: "var(--color-surface-muted)",
        color: "var(--color-muted)",
        border: "1px solid var(--color-border)",
        borderRadius: "999px",
      }}
    >
      Paused
    </span>
  );
}


function ChannelIcon({ type }: { type: string }) {
  if (type === "email") return <Mail className="w-3.5 h-3.5 shrink-0" aria-hidden />;
  if (type === "slack")
    return <MessageSquare className="w-3.5 h-3.5 shrink-0" aria-hidden />;
  return <Webhook className="w-3.5 h-3.5 shrink-0" aria-hidden />;
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
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(15,23,42,0.45)" }}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="w-full max-w-lg p-5"
        style={{
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: "5px",
          boxShadow: "0 20px 50px rgba(0,0,0,0.18)",
        }}
      >
        <h2
          className="text-[16px] font-semibold"
          style={{ color: "var(--color-ink)" }}
        >
          New feed subscription
        </h2>
        <div className="mt-4 space-y-4">
          <Field label="Name">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Critical phishing → SOC #soc"
              className="w-full text-[13px] px-2 py-1.5"
              style={{
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                borderRadius: "5px",
                color: "var(--color-ink)",
              }}
            />
          </Field>
          <Field
            label="Filter (JSON)"
            help={
              "Keys: severity, category, tags_any, tags_all, min_confidence, title_contains, title_regex. Empty object matches every alert."
            }
          >
            <textarea
              value={filterJson}
              onChange={(e) => setFilterJson(e.target.value)}
              rows={5}
              className="w-full font-mono text-[12px] px-2 py-1.5"
              style={{
                border: "1px solid var(--color-border)",
                background: "var(--color-surface-muted)",
                borderRadius: "5px",
                color: "var(--color-ink)",
              }}
            />
          </Field>
          <Field label="Delivery">
            <div className="flex gap-2">
              <select
                value={channelType}
                onChange={(e) =>
                  setChannelType(e.target.value as "webhook" | "email" | "slack")
                }
                className="text-[13px] px-2 py-1.5"
                style={{
                  border: "1px solid var(--color-border)",
                  background: "var(--color-canvas)",
                  borderRadius: "5px",
                  color: "var(--color-ink)",
                }}
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
                className="flex-1 text-[13px] px-2 py-1.5"
                style={{
                  border: "1px solid var(--color-border)",
                  background: "var(--color-canvas)",
                  borderRadius: "5px",
                  color: "var(--color-ink)",
                }}
              />
            </div>
          </Field>

          {error && (
            <div
              className="px-3 py-2 text-[12px]"
              style={{
                border: "1px solid rgba(239,68,68,0.3)",
                background: "rgba(239,68,68,0.06)",
                borderRadius: "5px",
                color: "var(--color-error-dark)",
              }}
            >
              {error}
            </div>
          )}
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={submitting}
            className="text-[13px] font-medium px-3 py-1.5"
            style={{
              border: "1px solid var(--color-border)",
              background: "var(--color-canvas)",
              borderRadius: "5px",
              color: "var(--color-ink)",
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={submitting || !name.trim() || !target.trim()}
            className="text-[13px] font-medium px-3 py-1.5"
            style={{
              background: "var(--color-accent)",
              color: "white",
              border: "1px solid var(--color-accent)",
              borderRadius: "5px",
              opacity: submitting || !name.trim() || !target.trim() ? 0.5 : 1,
            }}
          >
            Create
          </button>
        </div>
      </div>
    </div>
  );
}


function Field({
  label,
  help,
  children,
}: {
  label: string;
  help?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div
        className="text-[10px] uppercase tracking-[0.8px] font-semibold mb-1.5"
        style={{ color: "var(--color-muted)" }}
      >
        {label}
      </div>
      {children}
      {help && (
        <p
          className="text-[11px] mt-1.5"
          style={{ color: "var(--color-muted)" }}
        >
          {help}
        </p>
      )}
    </div>
  );
}
