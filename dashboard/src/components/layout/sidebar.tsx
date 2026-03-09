"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  AlertTriangle,
  Building2,
  Radar,
  Bot,
  FileText,
  Bell,
  Settings,
  Eye,
  Globe,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/utils";

const nav = [
  { label: "Dashboard", href: "/", icon: LayoutDashboard },
  { label: "Alerts", href: "/alerts", icon: AlertTriangle },
  { label: "Organizations", href: "/organizations", icon: Building2 },
  { label: "Attack Surface", href: "/surface", icon: Globe },
  { label: "Crawlers", href: "/crawlers", icon: Bot },
  { label: "Reports", href: "/reports", icon: FileText },
  { label: "Notifications", href: "/notifications", icon: Bell },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 bottom-0 w-[260px] bg-[#1C252E] flex flex-col z-40">
      {/* Logo */}
      <div className="h-[72px] flex items-center gap-3 px-6">
        <div className="w-9 h-9 rounded-lg bg-[#00A76F] flex items-center justify-center">
          <Eye className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-white text-[18px] font-bold tracking-wide">ARGUS</h1>
          <p className="text-[#919EAB] text-[10px] tracking-widest uppercase">Threat Intelligence</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 mt-2 space-y-0.5">
        {nav.map((item) => {
          const isActive =
            item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-[14px] font-medium transition-colors",
                isActive
                  ? "bg-[#00A76F]/12 text-[#5BE49B]"
                  : "text-[#919EAB] hover:bg-white/5 hover:text-white"
              )}
            >
              <Icon className="w-5 h-5 shrink-0" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-4 border-t border-white/8">
        <div className="flex items-center gap-2 text-[12px] text-[#637381]">
          <Shield className="w-4 h-4" />
          <span>Argus v0.1.0</span>
        </div>
      </div>
    </aside>
  );
}
