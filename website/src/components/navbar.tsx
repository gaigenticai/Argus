"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "./theme-provider";
import { useState, useEffect } from "react";
import { Menu, X, Sun, Moon, Shield } from "lucide-react";

const NAV_LINKS = [
  { label: "Features", href: "/features" },
  { label: "Platform", href: "/platform" },
  { label: "Pricing", href: "/pricing" },
  { label: "About", href: "/about" },
];

export function Navbar() {
  const pathname = usePathname();
  const { theme, toggle } = useTheme();
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  return (
    <nav
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        zIndex: 100,
        background: scrolled ? "var(--nav-bg)" : "transparent",
        backdropFilter: scrolled ? "blur(20px) saturate(1.6)" : "none",
        WebkitBackdropFilter: scrolled ? "blur(20px) saturate(1.6)" : "none",
        borderBottom: scrolled ? "1px solid var(--border)" : "1px solid transparent",
        transition: "all 0.35s ease",
      }}
    >
      <div
        style={{
          maxWidth: 1200,
          margin: "0 auto",
          padding: "0 24px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          height: 72,
        }}
      >
        {/* Logo */}
        <Link
          href="/"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            textDecoration: "none",
            color: scrolled || pathname !== "/" ? "var(--text)" : "#F4F6F8",
            transition: "color 0.3s",
          }}
        >
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: "linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Shield size={20} color="#fff" strokeWidth={2.5} />
          </div>
          <span style={{ fontSize: 20, fontWeight: 700, letterSpacing: "-0.02em" }}>
            ARGUS
          </span>
        </Link>

        {/* Desktop links */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
          className="desktop-nav"
        >
          {NAV_LINKS.map((link) => {
            const active = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                style={{
                  fontSize: 14,
                  fontWeight: 500,
                  padding: "8px 16px",
                  borderRadius: 8,
                  textDecoration: "none",
                  color: active
                    ? "var(--primary)"
                    : scrolled || pathname !== "/"
                      ? "var(--text-secondary)"
                      : "rgba(244,246,248,0.7)",
                  background: active ? "var(--surface)" : "transparent",
                  transition: "all 0.2s",
                }}
              >
                {link.label}
              </Link>
            );
          })}

          {/* Theme toggle */}
          <button
            onClick={toggle}
            style={{
              width: 40,
              height: 40,
              borderRadius: 10,
              border: "1px solid var(--border)",
              background: "var(--surface)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              color: "var(--text-secondary)",
              transition: "all 0.2s",
              marginLeft: 8,
            }}
            aria-label="Toggle theme"
          >
            {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
          </button>

          {/* CTA */}
          <Link
            href="https://app.argusai.xyz"
            target="_blank"
            style={{
              height: 40,
              padding: "0 20px",
              borderRadius: 10,
              background: "var(--primary)",
              color: "#fff",
              fontSize: 14,
              fontWeight: 600,
              display: "inline-flex",
              alignItems: "center",
              textDecoration: "none",
              marginLeft: 8,
              transition: "all 0.25s",
            }}
          >
            Open Dashboard
          </Link>
        </div>

        {/* Mobile hamburger */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="mobile-toggle"
          style={{
            display: "none",
            width: 40,
            height: 40,
            borderRadius: 10,
            border: "1px solid var(--border)",
            background: "var(--surface)",
            alignItems: "center",
            justifyContent: "center",
            cursor: "pointer",
            color: scrolled || pathname !== "/" ? "var(--text)" : "#F4F6F8",
          }}
          aria-label="Menu"
        >
          {mobileOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
      </div>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div
          style={{
            background: "var(--bg)",
            borderTop: "1px solid var(--border)",
            padding: "16px 24px 24px",
          }}
          className="mobile-drawer"
        >
          {NAV_LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              style={{
                display: "block",
                padding: "12px 0",
                fontSize: 16,
                fontWeight: 500,
                color: pathname === link.href ? "var(--primary)" : "var(--text-secondary)",
                textDecoration: "none",
                borderBottom: "1px solid var(--border)",
              }}
            >
              {link.label}
            </Link>
          ))}
          <div style={{ display: "flex", gap: 12, marginTop: 16 }}>
            <button
              onClick={toggle}
              style={{
                height: 44,
                padding: "0 16px",
                borderRadius: 10,
                border: "1px solid var(--border)",
                background: "var(--surface)",
                color: "var(--text-secondary)",
                fontSize: 14,
                fontWeight: 500,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: 8,
              }}
            >
              {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
              {theme === "dark" ? "Light" : "Dark"}
            </button>
            <Link
              href="https://app.argusai.xyz"
              target="_blank"
              style={{
                flex: 1,
                height: 44,
                borderRadius: 10,
                background: "var(--primary)",
                color: "#fff",
                fontSize: 14,
                fontWeight: 600,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                textDecoration: "none",
              }}
            >
              Open Dashboard
            </Link>
          </div>
        </div>
      )}

      <style>{`
        @media (max-width: 768px) {
          .desktop-nav { display: none !important; }
          .mobile-toggle { display: flex !important; }
        }
      `}</style>
    </nav>
  );
}
