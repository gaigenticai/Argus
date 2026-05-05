"use client";

import { useEffect, useMemo, useState } from "react";
import { Loader2, Search } from "lucide-react";

import { api, type Alert } from "@/lib/api";
import { useToast } from "@/components/shared/toast";

/** Modal for kicking off a fresh investigation against any alert (T62).
 *
 *  Title-prefix search filters the operator's recent alerts; clicking
 *  one fires POST /investigations/{alert_id} and resolves with the new
 *  investigation id so the caller can navigate / select it.
 */
export function RunInvestigationModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (newInvestigationId: string, alertId: string) => void;
}) {
  const { toast } = useToast();
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [q, setQ] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        // Cap at 50 newest — analyst either spots the right one in the
        // top-of-list or filters by typing. We avoid wiring a backend
        // search-by-title here; ?q= prefix filter is good enough.
        const list = await api.getAlerts({ limit: 50 });
        if (!alive) return;
        setAlerts(list);
      } catch (e) {
        if (!alive) return;
        toast(
          "error",
          e instanceof Error ? e.message : "Failed to load alerts",
        );
      }
    })();
    return () => {
      alive = false;
    };
  }, [toast]);

  // ESC closes.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase();
    if (!ql) return alerts || [];
    return (alerts || []).filter(
      (a) =>
        a.title.toLowerCase().includes(ql)
        || (a.summary || "").toLowerCase().includes(ql)
        || a.id.toLowerCase().includes(ql),
    );
  }, [alerts, q]);

  const run = async (alertId: string) => {
    setBusyId(alertId);
    try {
      const res = await api.investigations.create(alertId);
      toast(
        "success",
        res.status === "queued"
          ? "Investigation queued"
          : "Investigation already in flight — opening it",
      );
      onCreated(res.id, alertId);
    } catch (e) {
      toast(
        "error",
        e instanceof Error ? e.message : "Failed to queue investigation",
      );
    } finally {
      setBusyId(null);
    }
  };

  return (
    <>
      <div
        onClick={onClose}
        aria-hidden
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,0,0,0.32)",
          zIndex: 70,
        }}
      />
      <div
        role="dialog"
        aria-label="Run investigation"
        style={{
          position: "fixed",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
          width: "min(640px, 95vw)",
          maxHeight: "min(720px, 90vh)",
          background: "var(--color-canvas)",
          border: "1px solid var(--color-border)",
          borderRadius: 6,
          zIndex: 71,
          boxShadow: "0 16px 48px rgba(0,0,0,0.22)",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <header
          style={{
            padding: "14px 18px",
            borderBottom: "1px solid var(--color-border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <h3 className="text-[14px] font-semibold" style={{ color: "var(--color-ink)" }}>
            Run new investigation
          </h3>
          <button
            onClick={onClose}
            aria-label="Close"
            style={{
              background: "transparent",
              border: "none",
              color: "var(--color-muted)",
              fontSize: 18,
              cursor: "pointer",
              padding: 0,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </header>
        <div style={{ padding: "12px 18px", borderBottom: "1px solid var(--color-border)" }}>
          <div style={{ position: "relative" }}>
            <Search
              style={{
                width: 14,
                height: 14,
                position: "absolute",
                left: 10,
                top: "50%",
                transform: "translateY(-50%)",
                color: "var(--color-muted)",
              }}
            />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              autoFocus
              placeholder="Search recent alerts by title, summary, or id…"
              style={{
                width: "100%",
                height: 36,
                padding: "0 12px 0 30px",
                borderRadius: 4,
                border: "1px solid var(--color-border)",
                background: "var(--color-canvas)",
                color: "var(--color-ink)",
                fontSize: 13,
                outline: "none",
              }}
            />
          </div>
        </div>
        <div style={{ flex: 1, overflowY: "auto", padding: "8px" }}>
          {alerts === null ? (
            <div style={{ padding: "32px", textAlign: "center", color: "var(--color-muted)", fontSize: 12 }}>
              Loading…
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: "32px", textAlign: "center", color: "var(--color-muted)", fontSize: 12, fontStyle: "italic" }}>
              No alerts match. Try a different query.
            </div>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 4 }}>
              {filtered.map((a) => (
                <li key={a.id}>
                  <button
                    onClick={() => run(a.id)}
                    disabled={busyId !== null}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: "10px 12px",
                      borderRadius: 4,
                      border: "1px solid var(--color-border)",
                      background: "var(--color-canvas)",
                      cursor: busyId === a.id ? "wait" : "pointer",
                      transition: "background 0.15s",
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      opacity: busyId !== null && busyId !== a.id ? 0.5 : 1,
                    }}
                    onMouseEnter={(e) => {
                      if (busyId === null) e.currentTarget.style.background = "var(--color-surface-muted)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = "var(--color-canvas)";
                    }}
                  >
                    {busyId === a.id ? (
                      <Loader2 style={{ width: 14, height: 14 }} className="animate-spin" />
                    ) : (
                      <span
                        style={{
                          padding: "1px 6px",
                          borderRadius: 3,
                          background: "var(--color-surface-muted)",
                          color: "var(--color-body)",
                          fontSize: 9.5,
                          fontWeight: 700,
                          textTransform: "uppercase",
                          letterSpacing: "0.06em",
                        }}
                      >
                        {a.severity}
                      </span>
                    )}
                    <span
                      style={{
                        flex: 1,
                        minWidth: 0,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        fontSize: 13,
                        color: "var(--color-ink)",
                      }}
                    >
                      {a.title}
                    </span>
                    <span
                      style={{
                        fontFamily: "monospace",
                        fontSize: 10.5,
                        color: "var(--color-muted)",
                      }}
                    >
                      {a.id.slice(0, 8)}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </>
  );
}
