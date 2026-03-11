"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  AlertTriangle,
  Building2,
  Bot,
  FileText,
  Eye,
  Globe,
  Map,
  Activity,
  Crosshair,
  Users,
  Settings,
  LogOut,
  Database,
  Shield,
  Rss,
  Brain,
  Puzzle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/components/auth/auth-provider";

const NAV_INTELLIGENCE = [
  { label: "Threat Map", href: "/threat-map", icon: Map },
  { label: "Dashboard", href: "/", icon: LayoutDashboard },
  { label: "Alerts", href: "/alerts", icon: AlertTriangle },
  { label: "IOCs", href: "/iocs", icon: Crosshair },
  { label: "Threat Actors", href: "/actors", icon: Shield },
  { label: "Organizations", href: "/organizations", icon: Building2 },
  { label: "Attack Surface", href: "/surface", icon: Globe },
];

const NAV_OPS = [
  { label: "Feeds", href: "/feeds", icon: Rss },
  { label: "Sources", href: "/sources", icon: Database },
  { label: "Crawlers", href: "/crawlers", icon: Bot },
  { label: "Activity", href: "/activity", icon: Activity },
  { label: "Reports", href: "/reports", icon: FileText },
  { label: "Integrations", href: "/integrations", icon: Puzzle },
];

const NAV_ADMIN = [
  { label: "Settings", href: "/settings", icon: Settings },
];

function NavGroup({ label, items }: { label: string; items: typeof NAV_INTELLIGENCE }) {
  const pathname = usePathname();

  return (
    <div>
      <div className="px-4 pt-6 pb-2">
        <span className="text-[11px] font-bold uppercase tracking-[1.2px] text-grey-500">
          {label}
        </span>
      </div>
      <div className="space-y-0.5 px-3">
        {items.map((item) => {
          const isActive =
            item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 h-[44px] px-3 rounded-lg text-[14px] font-semibold transition-all duration-150",
                isActive
                  ? "bg-primary-lighter/[0.16] text-primary-light"
                  : "text-grey-500 hover:bg-white/[0.06] hover:text-grey-300"
              )}
            >
              <Icon className={cn("w-5 h-5 shrink-0", isActive ? "text-primary-light" : "text-grey-500")} />
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
    <aside className="fixed left-0 top-0 bottom-0 w-[280px] bg-grey-900 flex flex-col z-40">
      {/* Logo */}
      <div className="h-16 flex items-center gap-3 px-6 shrink-0">
        <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
          <Eye className="w-[18px] h-[18px] text-white" />
        </div>
        <div className="leading-none">
          <h1 className="text-white text-[16px] font-extrabold tracking-wider">ARGUS</h1>
          <p className="text-grey-600 text-[10px] tracking-[1.5px] uppercase mt-0.5">Threat Intel</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto">
        <NavGroup label="Intelligence" items={NAV_INTELLIGENCE} />
        <NavGroup label="Operations" items={NAV_OPS} />
        <NavGroup label="Admin" items={NAV_ADMIN} />
      </nav>

      {/* User info + Logout */}
      <div className="px-4 py-4 border-t border-white/[0.06]">
        {user ? (
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-grey-700 flex items-center justify-center text-white text-[12px] font-bold shrink-0">
              {user.display_name?.charAt(0)?.toUpperCase() || user.username?.charAt(0)?.toUpperCase() || "U"}
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-[13px] font-semibold text-grey-300 truncate">
                {user.display_name || user.username}
              </div>
              <div className="text-[11px] text-grey-500 capitalize">{user.role}</div>
            </div>
            <button
              onClick={logout}
              className="p-1.5 rounded-lg text-grey-500 hover:text-grey-300 hover:bg-white/[0.06] transition-colors"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <div className="text-[11px] text-grey-600 font-medium">
            Argus v0.1.0
          </div>
        )}
      </div>
    </aside>
  );
}
