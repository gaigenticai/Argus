"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Sparkles,
  Plus,
  CheckCircle2,
  Clock,
  XCircle,
  ArrowRight,
  Loader2,
  Building2,
} from "lucide-react";
import { api, type OnboardingSessionRecord, type Org } from "@/lib/api";
import { useToast } from "@/components/shared/toast";
import { timeAgo } from "@/lib/utils";

const STATE_BADGE: Record<string, { bg: string; color: string; icon: typeof Clock }> = {
  draft: { bg: "rgba(255,171,0,0.1)", color: "#B76E00", icon: Clock },
  completed: { bg: "rgba(0,167,111,0.1)", color: "#007B55", icon: CheckCircle2 },
  abandoned: { bg: "var(--color-surface-muted)", color: "var(--color-muted)", icon: XCircle },
};

const STEP_LABELS = ["Organization", "Infra", "People & Brand", "Vendors", "Review"];

export default function OnboardingIndexPage() {
  const router = useRouter();
  const { toast } = useToast();

  const [sessions, setSessions] = useState<OnboardingSessionRecord[]>([]);
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [bindOrgId, setBindOrgId] = useState<string>("");
  const [notes, setNotes] = useState("");

  useEffect(() => {
    void load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const [s, o] = await Promise.all([
        api.listOnboardingSessions({ limit: 50 }),
        api.getOrgs(),
      ]);
      setSessions(s);
      setOrgs(o);
    } catch (e) {
      toast("error", `Failed to load: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }

  async function startSession() {
    setCreating(true);
    try {
      const sess = await api.createOnboardingSession({
        organization_id: bindOrgId || undefined,
        notes: notes.trim() || undefined,
      });
      router.push(`/onboarding/${sess.id}`);
    } catch (e) {
      toast("error", `Failed to start session: ${(e as Error).message}`);
      setCreating(false);
    }
  }

  return (
    <div className="space-y-6">
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2 style={{ fontSize: "22px", fontWeight: 700, color: "var(--color-ink)", display: "flex", alignItems: "center", gap: "8px" }}>
            <Sparkles style={{ width: "24px", height: "24px", color: "var(--color-accent)" }} />
            Onboarding
          </h2>
          <p style={{ fontSize: "14px", color: "var(--color-muted)", marginTop: "2px" }}>
            Resumable 5-step wizard — register an organization and seed its asset registry.
          </p>
        </div>
        <NewSessionButton onClick={() => setShowCreate(true)} />
      </div>

      {loading ? (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "64px 0" }}>
          <Loader2 style={{ width: "24px", height: "24px", color: "var(--color-muted)" }} className="animate-spin" />
        </div>
      ) : sessions.length === 0 ? (
        <div style={{
          borderRadius: "5px",
          border: "2px dashed var(--color-border)",
          padding: "48px 24px",
          textAlign: "center",
        }}>
          <Sparkles style={{ width: "40px", height: "40px", margin: "0 auto", color: "var(--color-muted)" }} />
          <h3 style={{ marginTop: "16px", fontSize: "16px", fontWeight: 700, color: "var(--color-ink)" }}>
            No onboarding sessions yet
          </h3>
          <p style={{ fontSize: "14px", color: "var(--color-muted)", marginTop: "4px" }}>
            Start a new session to walk an organization through the 5-step setup.
          </p>
          <StartSessionButton onClick={() => setShowCreate(true)} />
        </div>
      ) : (
        <div style={{ borderRadius: "5px", border: "1px solid var(--color-border)", overflow: "hidden", background: "var(--color-canvas)" }}>
          <table className="w-full">
            <thead>
              <tr style={{ background: "var(--color-surface)", borderBottom: "1px solid var(--color-border)" }}>
                {["Session", "Organization", "State", "Step", "Updated", ""].map((h, i) => (
                  <th
                    key={i}
                    style={{
                      textAlign: i === 5 ? "right" : "left",
                      fontSize: "11.5px",
                      fontWeight: 700,
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      color: "var(--color-muted)",
                      padding: "10px 16px",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <SessionRow
                  key={s.id}
                  s={s}
                  orgName={
                    s.organization_id
                      ? orgs.find((o) => o.id === s.organization_id)?.name ?? "—"
                      : (s.step_data as { organization?: { name?: string } })?.organization?.name ?? "(new)"
                  }
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <CreateSessionModal
          orgs={orgs}
          bindOrgId={bindOrgId}
          setBindOrgId={setBindOrgId}
          notes={notes}
          setNotes={setNotes}
          creating={creating}
          onClose={() => setShowCreate(false)}
          onStart={startSession}
        />
      )}
    </div>
  );
}

function NewSessionButton({ onClick }: { onClick: () => void }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "8px",
        height: "40px",
        padding: "0 16px",
        borderRadius: "4px",
        border: "none",
        background: hov ? "#e64600" : "var(--color-accent)",
        color: "var(--color-on-dark)",
        fontSize: "14px",
        fontWeight: 700,
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <Plus style={{ width: "16px", height: "16px" }} />
      New session
    </button>
  );
}

function StartSessionButton({ onClick }: { onClick: () => void }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        marginTop: "16px",
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        height: "36px",
        padding: "0 16px",
        borderRadius: "4px",
        border: "none",
        background: hov ? "#e64600" : "var(--color-accent)",
        color: "var(--color-on-dark)",
        fontSize: "13px",
        fontWeight: 700,
        cursor: "pointer",
        transition: "background 0.15s",
      }}
    >
      <Plus style={{ width: "16px", height: "16px" }} />
      Start a session
    </button>
  );
}

function SessionRow({ s, orgName }: { s: OnboardingSessionRecord; orgName: string }) {
  const [hov, setHov] = useState(false);
  const [linkHov, setLinkHov] = useState(false);
  const badge = STATE_BADGE[s.state] ?? STATE_BADGE.draft;
  const Icon = badge.icon;
  return (
    <tr
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        borderBottom: "1px solid var(--color-border)",
        background: hov ? "var(--color-surface)" : "transparent",
        transition: "background 0.15s",
      }}
    >
      <td style={{ padding: "12px 16px", fontFamily: "monospace", fontSize: "13px", color: "var(--color-body)" }}>
        {s.id.slice(0, 8)}…
      </td>
      <td style={{ padding: "12px 16px", fontSize: "13px", color: "var(--color-ink)", display: "flex", alignItems: "center", gap: "8px" }}>
        <Building2 style={{ width: "16px", height: "16px", color: "var(--color-muted)" }} />
        {orgName}
      </td>
      <td style={{ padding: "12px 16px" }}>
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "4px",
          padding: "2px 8px",
          borderRadius: "4px",
          fontSize: "11px",
          fontWeight: 700,
          background: badge.bg,
          color: badge.color,
        }}>
          <Icon style={{ width: "12px", height: "12px" }} />
          {s.state}
        </span>
      </td>
      <td style={{ padding: "12px 16px", fontSize: "13px", color: "var(--color-body)" }}>
        {s.state === "completed"
          ? "—"
          : `${s.current_step}/5 · ${STEP_LABELS[s.current_step - 1] ?? ""}`}
      </td>
      <td style={{ padding: "12px 16px", fontSize: "13px", color: "var(--color-muted)" }}>
        {timeAgo(s.updated_at)}
      </td>
      <td style={{ padding: "12px 16px", textAlign: "right" }}>
        <Link
          href={`/onboarding/${s.id}`}
          onMouseEnter={() => setLinkHov(true)}
          onMouseLeave={() => setLinkHov(false)}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "4px",
            fontSize: "13px",
            fontWeight: 600,
            color: linkHov ? "#e64600" : "var(--color-accent)",
            textDecoration: "none",
            transition: "color 0.15s",
          }}
        >
          {s.state === "draft" ? "Resume" : "View"}
          <ArrowRight style={{ width: "14px", height: "14px" }} />
        </Link>
      </td>
    </tr>
  );
}

function CreateSessionModal({
  orgs,
  bindOrgId,
  setBindOrgId,
  notes,
  setNotes,
  creating,
  onClose,
  onStart,
}: {
  orgs: Org[];
  bindOrgId: string;
  setBindOrgId: (v: string) => void;
  notes: string;
  setNotes: (v: string) => void;
  creating: boolean;
  onClose: () => void;
  onStart: () => void;
}) {
  const [cancelHov, setCancelHov] = useState(false);
  const [startHov, setStartHov] = useState(false);

  return (
    <div style={{
      position: "fixed",
      inset: 0,
      zIndex: 40,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "rgba(32,21,21,0.4)",
    }}>
      <div style={{
        width: "100%",
        maxWidth: "520px",
        borderRadius: "8px",
        background: "var(--color-canvas)",
        padding: "24px",
        boxShadow: "0 20px 60px rgba(0,0,0,0.25)",
      }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
          <h3 style={{ fontSize: "18px", fontWeight: 700, color: "var(--color-ink)" }}>Start onboarding session</h3>
          <button
            onClick={onClose}
            style={{
              background: "none",
              border: "none",
              color: "var(--color-muted)",
              cursor: "pointer",
              fontSize: "18px",
              lineHeight: 1,
              padding: "4px",
            }}
          >
            ✕
          </button>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div>
            <label style={{ fontSize: "11.5px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", display: "block", marginBottom: "4px" }}>
              Bind to existing organization (optional)
            </label>
            <select
              value={bindOrgId}
              onChange={(e) => setBindOrgId(e.target.value)}
              style={{
                width: "100%",
                height: "40px",
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-ink)",
                padding: "0 12px",
                fontSize: "14px",
                outline: "none",
              }}
            >
              <option value="">— Create a new organization at completion —</option>
              {orgs.map((o) => (
                <option key={o.id} value={o.id}>{o.name}</option>
              ))}
            </select>
            <p style={{ fontSize: "12px", color: "var(--color-muted)", marginTop: "4px" }}>
              Pick an org to add more assets to it; leave empty to start fresh.
            </p>
          </div>
          <div>
            <label style={{ fontSize: "11.5px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--color-muted)", display: "block", marginBottom: "4px" }}>
              Notes (optional)
            </label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              style={{
                width: "100%",
                borderRadius: "4px",
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-ink)",
                padding: "8px 12px",
                fontSize: "14px",
                outline: "none",
                resize: "none",
              }}
            />
          </div>
        </div>
        <div style={{ marginTop: "24px", display: "flex", justifyContent: "flex-end", gap: "8px" }}>
          <button
            onClick={onClose}
            onMouseEnter={() => setCancelHov(true)}
            onMouseLeave={() => setCancelHov(false)}
            style={{
              height: "40px",
              padding: "0 16px",
              borderRadius: "4px",
              border: "1px solid var(--color-border)",
              background: cancelHov ? "var(--color-surface-muted)" : "var(--color-canvas)",
              color: "var(--color-body)",
              fontSize: "14px",
              fontWeight: 600,
              cursor: "pointer",
              transition: "background 0.15s",
            }}
          >
            Cancel
          </button>
          <button
            onClick={onStart}
            disabled={creating}
            onMouseEnter={() => setStartHov(true)}
            onMouseLeave={() => setStartHov(false)}
            style={{
              height: "40px",
              padding: "0 16px",
              borderRadius: "4px",
              border: "none",
              background: creating ? "var(--color-surface-muted)" : startHov ? "#e64600" : "var(--color-accent)",
              color: creating ? "var(--color-muted)" : "var(--color-on-dark)",
              fontSize: "14px",
              fontWeight: 700,
              cursor: creating ? "not-allowed" : "pointer",
              opacity: creating ? 0.7 : 1,
              transition: "background 0.15s",
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            {creating ? <Loader2 style={{ width: "16px", height: "16px" }} className="animate-spin" /> : "Start"}
          </button>
        </div>
      </div>
    </div>
  );
}
