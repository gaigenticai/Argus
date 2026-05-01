"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  AlertTriangle,
  Building2,
  Bot,
  FileText,
  Globe,
  Map,
  Activity,
  Crosshair,
  Settings,
  LogOut,
  Database,
  Shield,
  Rss,
  Puzzle,
  Sparkles,
  Briefcase,
  Bell,
  ShieldCheck,
  ShieldAlert,
  Network,
  Workflow,
  GanttChart,
  Eye,
  Megaphone,
  Newspaper,
  Lock,
  ScrollText,
  ClipboardList,
  SlidersHorizontal,
  Layers,
  Plug,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/components/auth/auth-provider";
import { ArgusLogo } from "@/components/shared/argus-logo";

const NAV_OVERVIEW = [
  { label: "Dashboard", href: "/", icon: LayoutDashboard },
  { label: "Exec Summary", href: "/exec-summary", icon: GanttChart },
  { label: "Threat Map", href: "/threat-map", icon: Map },
];

const NAV_RESPONSE = [
  { label: "Cases", href: "/cases", icon: Briefcase },
  { label: "Takedowns", href: "/takedowns", icon: Workflow },
  { label: "Alerts", href: "/alerts", icon: AlertTriangle },
  { label: "Investigations", href: "/investigations", icon: Sparkles },
];

const NAV_BRAND = [
  { label: "Brand Protection", href: "/brand", icon: ShieldCheck },
  { label: "Brand Defender", href: "/brand-defender", icon: Sparkles },
  { label: "Exposures", href: "/exposures", icon: ShieldAlert },
  { label: "Attack Surface", href: "/surface", icon: Globe },
  { label: "TPRM", href: "/tprm", icon: Network },
];

const NAV_INTEL = [
  { label: "IOCs", href: "/iocs", icon: Crosshair },
  { label: "Threat Actors", href: "/actors", icon: Shield },
  { label: "Threat Hunter", href: "/threat-hunter", icon: Sparkles },
  { label: "MITRE ATT&CK", href: "/mitre", icon: Layers },
  { label: "CVE / KEV", href: "/intel", icon: Eye },
  { label: "Advisories", href: "/advisories", icon: Megaphone },
  { label: "News", href: "/news", icon: Newspaper },
];

const NAV_GOVERNANCE = [
  { label: "DLP & Leakage", href: "/leakage", icon: Lock },
  { label: "DMARC", href: "/dmarc", icon: ScrollText },
  { label: "Notifications", href: "/notifications", icon: Bell },
  { label: "Evidence Vault", href: "/evidence", icon: FileText },
  { label: "Retention", href: "/retention", icon: ClipboardList },
];

const NAV_OPS = [
  { label: "Organizations", href: "/organizations", icon: Building2 },
  { label: "Onboarding", href: "/onboarding", icon: Sparkles },
  { label: "Feeds", href: "/feeds", icon: Rss },
  { label: "Sources", href: "/sources", icon: Database },
  { label: "Crawlers", href: "/crawlers", icon: Bot },
  { label: "Activity", href: "/activity", icon: Activity },
  { label: "Reports", href: "/reports", icon: FileText },
  { label: "Compliance", href: "/compliance", icon: ClipboardList },
  { label: "Integrations", href: "/integrations", icon: Puzzle },
  { label: "Connectors", href: "/connectors", icon: Plug },
];

const NAV_ADMIN = [
  { label: "Agent Activity", href: "/agent-activity", icon: Sparkles },
  { label: "Agent Settings", href: "/agent-settings", icon: SlidersHorizontal },
  { label: "Runtime Config", href: "/admin", icon: SlidersHorizontal },
  { label: "Settings", href: "/settings", icon: Settings },
];

function NavGroup({ label, items }: { label: string; items: typeof NAV_OVERVIEW }) {
  const pathname = usePathname();

  return (
    <div>
      <div className="px-5 pt-5 pb-1.5">
        <span
          className="text-[10px] font-semibold uppercase tracking-[1.2px]"
          style={{ color: "var(--color-muted)" }}
        >
          {label}
        </span>
      </div>
      <div className="px-2 space-y-px">
        {items.map((item) => {
          const isActive =
            item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-2.5 h-9 px-3 text-[13px] font-medium transition-colors relative",
                isActive ? "rounded-[4px]" : "rounded-[4px]"
              )}
              style={
                isActive
                  ? {
                      background: "var(--color-surface-muted)",
                      color: "var(--color-ink)",
                      borderLeft: "2px solid var(--color-accent)",
                      paddingLeft: "10px",
                    }
                  : {
                      color: "var(--color-body)",
                      borderLeft: "2px solid transparent",
                      paddingLeft: "10px",
                    }
              }
              onMouseEnter={(e) => {
                if (!isActive) {
                  (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
                  (e.currentTarget as HTMLElement).style.color = "var(--color-ink)";
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  (e.currentTarget as HTMLElement).style.background = "";
                  (e.currentTarget as HTMLElement).style.color = "var(--color-body)";
                }
              }}
            >
              <Icon
                className="w-[15px] h-[15px] shrink-0"
                style={{ color: isActive ? "var(--color-accent)" : "var(--color-muted)" }}
                strokeWidth={isActive ? 2.25 : 1.75}
              />
              {item.label}
            </Link>
          );
        })}
      </div>
    </div>
  );
}

export function Sidebar() {
  const { user, logout } = useAuth();

  return (
    <aside
      className="fixed left-0 top-0 bottom-0 w-[240px] flex flex-col z-40"
      style={{
        background: "var(--color-surface)",
        borderRight: "1px solid var(--color-border)",
      }}
    >
      {/* Wordmark */}
      <div
        className="h-14 flex items-center gap-2.5 px-5 shrink-0"
        style={{ borderBottom: "1px solid var(--color-border)" }}
      >
        <ArgusLogo size={28} />
        <div className="leading-none">
          <h1
            className="text-[16px] font-semibold tracking-[-0.02em]"
            style={{ color: "var(--color-ink)" }}
          >
            Argus
          </h1>
          <p
            className="text-[9px] tracking-[1.2px] uppercase mt-0.5 font-semibold"
            style={{ color: "var(--color-muted)" }}
          >
            The All Seeing
          </p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-2">
        <NavGroup label="Overview" items={NAV_OVERVIEW} />
        <NavGroup label="Response" items={NAV_RESPONSE} />
        <NavGroup label="Brand & Surface" items={NAV_BRAND} />
        <NavGroup label="Intelligence" items={NAV_INTEL} />
        <NavGroup label="Governance" items={NAV_GOVERNANCE} />
        <NavGroup label="Operations" items={NAV_OPS} />
        <NavGroup label="Admin" items={NAV_ADMIN} />
      </nav>

      {/* Identity + logout */}
      <div
        className="px-4 py-3"
        style={{ borderTop: "1px solid var(--color-border)" }}
      >
        {user ? (
          <div className="flex items-center gap-2.5">
            <div
              className="w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-semibold shrink-0"
              style={{
                background: "var(--color-accent)",
                color: "#fffefb",
              }}
            >
              {user.display_name?.charAt(0)?.toUpperCase() ||
                user.username?.charAt(0)?.toUpperCase() ||
                "U"}
            </div>
            <div className="flex-1 min-w-0">
              <div
                className="text-[12px] font-semibold truncate"
                style={{ color: "var(--color-ink)" }}
              >
                {user.display_name || user.username}
              </div>
              <div
                className="text-[10px] capitalize"
                style={{ color: "var(--color-muted)" }}
              >
                {user.role}
              </div>
            </div>
            <button
              onClick={logout}
              className="p-1.5 transition-colors"
              style={{ color: "var(--color-muted)", borderRadius: "4px" }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLElement).style.background = "var(--color-surface-muted)";
                (e.currentTarget as HTMLElement).style.color = "var(--color-ink)";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.background = "";
                (e.currentTarget as HTMLElement).style.color = "var(--color-muted)";
              }}
              title="Logout"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        ) : (
          <div
            className="text-[11px] font-medium"
            style={{ color: "var(--color-muted)" }}
          >
            Argus v0.1.0
          </div>
        )}
      </div>
    </aside>
  );
}
