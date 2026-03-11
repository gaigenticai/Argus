"use client";

import Link from "next/link";
import { ArgusLogo } from "./argus-logo";

const LINKS = {
  Product: [
    { label: "Features", href: "/features" },
    { label: "Platform", href: "/platform" },
    { label: "Pricing", href: "/pricing" },
    { label: "Dashboard", href: "https://app.argusai.xyz" },
  ],
  Company: [
    { label: "About", href: "/about" },
    { label: "Contact", href: "/about#contact" },
  ],
  Legal: [
    { label: "Privacy Policy", href: "/privacy" },
    { label: "Terms of Service", href: "/terms" },
    { label: "Security", href: "/security" },
  ],
};

export function Footer() {
  return (
    <footer
      style={{
        background: "var(--bg-alt)",
        borderTop: "1px solid var(--border)",
        padding: "80px 0 40px",
      }}
    >
      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 24px" }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1.5fr repeat(3, 1fr)",
            gap: 48,
          }}
          className="footer-grid"
        >
          {/* Brand column */}
          <div>
            <Link
              href="/"
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                textDecoration: "none",
                color: "var(--text)",
                marginBottom: 16,
              }}
            >
              <ArgusLogo size={44} />
              <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.1 }}>
                <span style={{ fontSize: 18, fontWeight: 700, letterSpacing: "0.06em" }}>
                  ARGUS
                </span>
                <span style={{ fontSize: 9, fontWeight: 500, letterSpacing: "0.14em", opacity: 0.55 }}>
                  THE ALL SEEING
                </span>
              </div>
            </Link>
            <p
              style={{
                fontSize: 14,
                lineHeight: 1.7,
                color: "var(--text-muted)",
                maxWidth: 280,
              }}
            >
              AI-powered threat intelligence platform. Real-time global monitoring,
              agentic triage, and unified security operations.
            </p>
            <div style={{ marginTop: 24, display: "flex", gap: 8 }}>
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "4px 12px",
                  borderRadius: 20,
                  fontSize: 12,
                  fontWeight: 600,
                  background: "rgba(0,167,111,0.1)",
                  color: "var(--primary)",
                  border: "1px solid rgba(0,167,111,0.15)",
                }}
              >
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--success)" }} />
                All systems operational
              </span>
            </div>
          </div>

          {/* Link columns */}
          {Object.entries(LINKS).map(([title, links]) => (
            <div key={title}>
              <h4
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  color: "var(--text)",
                  marginBottom: 20,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                {title}
              </h4>
              <ul style={{ listStyle: "none" }}>
                {links.map((link) => (
                  <li key={link.label} style={{ marginBottom: 12 }}>
                    <Link
                      href={link.href}
                      style={{
                        fontSize: 14,
                        color: "var(--text-muted)",
                        textDecoration: "none",
                        transition: "color 0.2s",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.color = "var(--primary)")}
                      onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-muted)")}
                    >
                      {link.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div
          style={{
            marginTop: 64,
            paddingTop: 24,
            borderTop: "1px solid var(--border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 16,
          }}
        >
          <p style={{ fontSize: 13, color: "var(--text-muted)" }}>
            &copy; {new Date().getFullYear()} Argus. All rights reserved.
          </p>
          <p style={{ fontSize: 13, color: "var(--text-muted)" }}>
            Protecting organizations worldwide.
          </p>
        </div>
      </div>

      <style>{`
        @media (max-width: 768px) {
          .footer-grid {
            grid-template-columns: 1fr 1fr !important;
          }
        }
        @media (max-width: 480px) {
          .footer-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </footer>
  );
}
