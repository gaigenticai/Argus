"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Bell, Search, X, Building2, Check, ShieldCheck, ShieldAlert } from "lucide-react";
import { api, type Alert, type Org, type OrgDomainListItem } from "@/lib/api";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { useAuth } from "@/components/auth/auth-provider";

// localStorage key + global event used by other dashboard pages so a
// switcher click in the header instantly updates whatever's mounted.
// Several pages already read this key directly (alerts/leakage/tprm/
// evidence/etc.); the event is the new bit so the dashboard root
// can re-fetch without a full route change.
const ORG_KEY = "argus_org_id";
const ORG_CHANGED_EVENT = "argus:org-changed";

export function Header() {
  const router = useRouter();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [alertResults, setAlertResults] = useState<Alert[]>([]);
  const [orgResults, setOrgResults] = useState<Org[]>([]);
  const [searching, setSearching] = useState(false);
  const [unreviewed, setUnreviewed] = useState(0);
  const [pendingApprovals, setPendingApprovals] = useState(0);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const wrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    async function fetchCount() {
      try {
        const stats = await api.getAlertStats();
        setUnreviewed(stats.by_status?.new || 0);
      } catch {}
    }
    fetchCount();
    const interval = setInterval(fetchCount, 30000);
    return () => clearInterval(interval);
  }, []);

  // Pending-approvals counter — admins only. Polls every 30s. The
  // queue is tiny (rarely more than a handful) so this is cheap.
  // We read the org from localStorage so the badge matches whatever
  // org the user last picked, without re-plumbing org state up here.
  useEffect(() => {
    if (!isAdmin) {
      setPendingApprovals(0);
      return;
    }
    async function fetchPending() {
      const orgId = typeof window !== "undefined"
        ? localStorage.getItem(ORG_KEY)
        : null;
      if (!orgId) return;
      try {
        const r = await api.exec.playbookPendingApprovals({
          organization_id: orgId,
          limit: 100,
        });
        setPendingApprovals(r.total || 0);
      } catch {}
    }
    fetchPending();
    const interval = setInterval(fetchPending, 30000);
    function onOrgChange() { void fetchPending(); }
    window.addEventListener(ORG_CHANGED_EVENT, onOrgChange);
    return () => {
      clearInterval(interval);
      window.removeEventListener(ORG_CHANGED_EVENT, onOrgChange);
    };
  }, [isAdmin]);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    if (!query.trim()) {
      setAlertResults([]);
      setOrgResults([]);
      setOpen(false);
      return;
    }
    debounceRef.current = setTimeout(async () => {
      setSearching(true);
      try {
        const [alerts, orgs] = await Promise.all([
          api.searchAlerts(query),
          api.searchOrgs(query),
        ]);
        setAlertResults(alerts);
        setOrgResults(orgs);
        setOpen(true);
      } catch {}
      setSearching(false);
    }, 300);
  }, [query]);

  const hasResults = alertResults.length > 0 || orgResults.length > 0;

  return (
    <header
      className="sticky top-0 z-30 h-14 flex items-center justify-between px-6"
      style={{
        background: "var(--color-canvas)",
        borderBottom: "1px solid var(--color-border)",
      }}
    >
      <div ref={wrapperRef} className="relative flex items-center flex-1 max-w-md">
        <div className="relative w-full">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none"
            style={{ color: "var(--color-muted)" }}
          />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search alerts, organizations…"
            className="w-full h-9 pl-9 pr-8 text-[13px] outline-none transition-colors"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: "5px",
              color: "var(--color-ink)",
            }}
            onFocus={(e) => {
              (e.target as HTMLInputElement).style.borderColor = "var(--color-accent)";
            }}
            onBlur={(e) => {
              (e.target as HTMLInputElement).style.borderColor = "var(--color-border)";
            }}
          />
          {query && (
            <button
              onClick={() => { setQuery(""); setOpen(false); }}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-0.5 transition-colors"
              style={{ color: "var(--color-muted)", borderRadius: "3px" }}
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {open && (
          <div
            className="absolute top-full left-0 right-0 mt-1 overflow-hidden z-50 max-h-[380px] overflow-y-auto"
            style={{
              background: "var(--color-canvas)",
              border: "1px solid var(--color-border)",
              borderRadius: "5px",
              boxShadow: "var(--shadow-z16)",
            }}
          >
            {searching && (
              <div
                className="px-4 py-3 text-[12px]"
                style={{ color: "var(--color-muted)" }}
              >
                Searching…
              </div>
            )}
            {!searching && !hasResults && (
              <div
                className="px-4 py-6 text-center text-[13px]"
                style={{ color: "var(--color-muted)" }}
              >
                No results for &ldquo;{query}&rdquo;
              </div>
            )}

            {orgResults.length > 0 && (
              <div>
                <div
                  className="px-4 py-2 text-[10px] font-semibold uppercase tracking-[0.8px]"
                  style={{
                    color: "var(--color-muted)",
                    background: "var(--color-surface-muted)",
                    borderBottom: "1px solid var(--color-border)",
                  }}
                >
                  Organizations
                </div>
                {orgResults.map((org) => (
                  <button
                    key={org.id}
                    onClick={() => { router.push(`/organizations`); setOpen(false); setQuery(""); }}
                    className="w-full px-4 py-2.5 text-left flex items-center gap-3 transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "";
                    }}
                  >
                    <span
                      className="w-7 h-7 flex items-center justify-center text-[11px] font-bold shrink-0"
                      style={{
                        background: "var(--color-surface-muted)",
                        color: "var(--color-body)",
                        borderRadius: "4px",
                        border: "1px solid var(--color-border)",
                      }}
                    >
                      {org.name.charAt(0)}
                    </span>
                    <div>
                      <div className="text-[13px] font-semibold" style={{ color: "var(--color-ink)" }}>
                        {org.name}
                      </div>
                      {org.industry && (
                        <div className="text-[11px]" style={{ color: "var(--color-muted)" }}>
                          {org.industry}
                        </div>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            )}

            {alertResults.length > 0 && (
              <div>
                <div
                  className="px-4 py-2 text-[10px] font-semibold uppercase tracking-[0.8px]"
                  style={{
                    color: "var(--color-muted)",
                    background: "var(--color-surface-muted)",
                    borderBottom: "1px solid var(--color-border)",
                  }}
                >
                  Alerts
                </div>
                {alertResults.map((alert) => (
                  <button
                    key={alert.id}
                    onClick={() => { router.push(`/alerts/${alert.id}`); setOpen(false); setQuery(""); }}
                    className="w-full px-4 py-2.5 text-left flex items-center gap-3 transition-colors"
                    style={{ borderBottom: "1px solid var(--color-border)" }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.background = "";
                    }}
                  >
                    <SeverityBadge severity={alert.severity} />
                    <div className="min-w-0 flex-1">
                      <div
                        className="text-[13px] font-semibold truncate"
                        style={{ color: "var(--color-ink)" }}
                      >
                        {alert.title}
                      </div>
                      <div
                        className="text-[11px] truncate"
                        style={{ color: "var(--color-muted)" }}
                      >
                        {alert.summary}
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex items-center gap-2">
        <OrgScopeSwitcher />
        {isAdmin && pendingApprovals > 0 && (
          <button
            onClick={() => router.push("/playbooks?tab=approvals")}
            title={`${pendingApprovals} playbook ${pendingApprovals === 1 ? "run" : "runs"} pending approval`}
            className="relative p-2 transition-colors"
            style={{ borderRadius: "5px", color: "var(--color-warning-dark)" }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLElement).style.background = "";
            }}
          >
            <ShieldAlert className="w-4 h-4" />
            <span
              className="absolute top-0.5 right-0.5 min-w-[16px] h-[16px] flex items-center justify-center text-[9px] font-bold px-1"
              style={{
                background: "var(--color-warning-dark)",
                color: "#fffefb",
                borderRadius: "20px",
              }}
            >
              {pendingApprovals > 99 ? "99+" : pendingApprovals}
            </span>
          </button>
        )}
        <button
          onClick={() => router.push("/alerts?status=new")}
          className="relative p-2 transition-colors"
          style={{ borderRadius: "5px", color: "var(--color-body)" }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "";
          }}
        >
          <Bell className="w-4 h-4" />
          {unreviewed > 0 && (
            <span
              className="absolute top-0.5 right-0.5 min-w-[16px] h-[16px] flex items-center justify-center text-[9px] font-bold px-1"
              style={{
                background: "var(--color-accent)",
                color: "#fffefb",
                borderRadius: "20px",
              }}
            >
              {unreviewed > 99 ? "99+" : unreviewed}
            </span>
          )}
        </button>
      </div>
    </header>
  );
}


/**
 * <OrgScopeSwitcher /> — identity pill in the header that always
 * shows the currently-scoped org's name + its primary verified
 * domain (with a shield indicating verification state). Clicking it
 * opens a dropdown to switch orgs when multiple exist.
 *
 * The verified domain — not the name — is the org's identity anchor
 * (anyone can type a name; only the domain owner can publish a TXT
 * record). Surfacing it in the header makes "who are we protecting"
 * unambiguous on every page.
 *
 * Source of truth: ``localStorage[argus_org_id]``. On change we
 * dispatch ``argus:org-changed`` so the dashboard root + any other
 * listening page can re-fetch without a route navigation.
 */
function OrgScopeSwitcher() {
  const router = useRouter();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [orgId, setOrgId] = useState<string>("");
  const [domains, setDomains] = useState<OrgDomainListItem[]>([]);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    void (async () => {
      try {
        const list = await api.getOrgs();
        setOrgs(list);
        const stored = window.localStorage.getItem(ORG_KEY) || "";
        // If the stored id no longer maps to an org (deleted, fresh
        // browser, etc.), fall back to the first user-created org;
        // failing that the first one.
        const valid = list.find((o) => o.id === stored);
        const fallback = list[0]?.id || "";
        const next = valid ? stored : fallback;
        setOrgId(next);
        if (!valid && fallback) {
          window.localStorage.setItem(ORG_KEY, fallback);
        }
      } catch {
        // Best-effort — switcher just hides if the org fetch fails.
      }
    })();
  }, []);

  // Re-fetch domains whenever the scoped org changes (initial mount
  // sets orgId; OrgScopeSwitcher click does too). Also listens for
  // the global event so other surfaces (e.g. Settings → Domains
  // verifying a domain) refresh the badge live.
  useEffect(() => {
    if (!orgId) {
      setDomains([]);
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const list = await api.orgDomains.list(orgId);
        if (!cancelled) setDomains(list);
      } catch {
        if (!cancelled) setDomains([]);
      }
    })();
    function refresh() {
      void (async () => {
        try {
          const list = await api.orgDomains.list(orgId);
          if (!cancelled) setDomains(list);
        } catch {}
      })();
    }
    window.addEventListener(ORG_CHANGED_EVENT, refresh);
    window.addEventListener("argus:domains-changed", refresh);
    return () => {
      cancelled = true;
      window.removeEventListener(ORG_CHANGED_EVENT, refresh);
      window.removeEventListener("argus:domains-changed", refresh);
    };
  }, [orgId]);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  if (orgs.length === 0) return null;

  const current = orgs.find((o) => o.id === orgId);
  const primary = domains.find((d) => d.is_primary) ?? domains[0];
  const isVerified = primary?.verification_status === "verified";
  const hasDomain = !!primary;
  const isMultiOrg = orgs.length > 1;

  const pick = (id: string) => {
    setOrgId(id);
    window.localStorage.setItem(ORG_KEY, id);
    window.dispatchEvent(new CustomEvent(ORG_CHANGED_EVENT, { detail: { orgId: id } }));
    setOpen(false);
  };

  // Shield icon + tooltip reflect verification state. Operators learn
  // to read this at a glance: green shield = "we have proof you own
  // this", warning shield = "anyone could be claiming to be you".
  const shield = isVerified ? (
    <ShieldCheck
      className="w-3.5 h-3.5 shrink-0"
      style={{ color: "var(--color-success, #10B981)" }}
    />
  ) : hasDomain ? (
    <ShieldAlert
      className="w-3.5 h-3.5 shrink-0"
      style={{ color: "var(--color-accent)" }}
    />
  ) : null;

  const tooltip = !current
    ? "No organisation scoped"
    : !hasDomain
    ? `${current.name} — no identity domain set. Visit Settings → Domains.`
    : isVerified
    ? `${current.name} — identity verified via DNS TXT on ${primary.domain}`
    : `${current.name} — ownership of ${primary.domain} not yet proven. Verify in Settings → Domains.`;

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => {
          if (isMultiOrg) {
            setOpen((x) => !x);
          } else {
            // Single-tenant: clicking the badge jumps to where the
            // operator manages it (the source of truth).
            router.push("/settings");
          }
        }}
        className="inline-flex items-center gap-2 h-8 px-2.5"
        title={tooltip}
        style={{
          background: "var(--color-surface)",
          border: "1px solid var(--color-border)",
          borderRadius: 4,
          color: "var(--color-ink)",
          fontSize: 12,
          fontWeight: 600,
          cursor: "pointer",
          maxWidth: 320,
        }}
      >
        <Building2 className="w-3.5 h-3.5 shrink-0" style={{ color: "var(--color-muted)" }} />
        <span className="truncate" style={{ maxWidth: 140 }}>
          {current?.name ?? "Choose org"}
        </span>
        {primary && (
          <>
            <span style={{ color: "var(--color-muted)", fontWeight: 400 }}>·</span>
            <code
              className="truncate"
              style={{
                fontFamily: "var(--font-mono, monospace)",
                fontWeight: 500,
                fontSize: 11.5,
                color: isVerified ? "var(--color-body)" : "var(--color-muted)",
                maxWidth: 140,
              }}
            >
              {primary.domain}
            </code>
          </>
        )}
        {shield}
      </button>
      {isMultiOrg && open && (
        <div
          className="absolute right-0 mt-1 z-50 max-h-[360px] overflow-y-auto"
          style={{
            background: "var(--color-canvas)",
            border: "1px solid var(--color-border)",
            borderRadius: 5,
            boxShadow: "var(--shadow-z16)",
            minWidth: 240,
          }}
        >
          {orgs.map((o) => (
            <button
              key={o.id}
              onClick={() => pick(o.id)}
              className="w-full px-3 py-2 text-left flex items-center gap-2"
              style={{
                background: "transparent",
                border: "none",
                cursor: "pointer",
                color: "var(--color-ink)",
                fontSize: 12,
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.background = "transparent";
              }}
            >
              <span className="flex-1 truncate font-semibold">{o.name}</span>
              {o.id === orgId && (
                <Check className="w-3.5 h-3.5 shrink-0" style={{ color: "var(--color-accent)" }} />
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
