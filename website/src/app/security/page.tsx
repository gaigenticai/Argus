"use client";

import { AnimateIn } from "@/components/animate-in";
import {
  Shield,
  ShieldCheck,
  Lock,
  Server,
  Code,
  KeyRound,
  Database,
  Eye,
  Scale,
  AlertTriangle,
  Handshake,
  Mail,
  CheckCircle2,
  FileKey,
  Users,
  Clock,
  Globe,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

/* ─────────────────────── Section data ─────────────────────── */

interface SecuritySection {
  id: string;
  icon: LucideIcon;
  title: string;
  color: string;
  paragraphs: string[];
  items?: string[];
}

const SECTIONS: SecuritySection[] = [
  {
    id: "overview",
    icon: ShieldCheck,
    title: "Security Overview",
    color: "var(--primary)",
    paragraphs: [
      "Argus is a threat intelligence platform built by a security company, for security teams. Security is not an afterthought or a compliance checkbox — it is the foundation of everything we build. We hold ourselves to the same standards we help our customers achieve.",
      "Our security program is designed around defense-in-depth: multiple overlapping layers of protection across infrastructure, application, data, and operations. We continuously evaluate and improve our posture because the threat landscape never stops evolving — and neither do we.",
    ],
  },
  {
    id: "infrastructure",
    icon: Server,
    title: "Infrastructure Security",
    color: "var(--primary)",
    paragraphs: [
      "Our infrastructure is architected for isolation, resilience, and auditability from the ground up.",
    ],
    items: [
      "All data encrypted at rest using AES-256 with regularly rotated keys managed through dedicated key management services",
      "All data in transit encrypted with TLS 1.3 — no exceptions, no fallback to older protocols",
      "Strict network segmentation with isolated environments for production, staging, and development workloads",
      "Infrastructure deployed as code (IaC) with version-controlled, peer-reviewed configuration changes",
      "Regular third-party penetration testing conducted by qualified security firms, with remediation tracked to closure",
      "Automated vulnerability scanning across all hosts, containers, and cloud configurations on a continuous basis",
      "DDoS mitigation and WAF protections at the edge layer",
    ],
  },
  {
    id: "application",
    icon: Code,
    title: "Application Security",
    color: "var(--secondary, #8E33FF)",
    paragraphs: [
      "We build secure software by design, embedding security into every phase of the development lifecycle.",
    ],
    items: [
      "Proactive prevention of OWASP Top 10 vulnerabilities including injection, XSS, CSRF, SSRF, and broken access control",
      "Strict input validation and output encoding on all user-supplied data across every API surface",
      "Parameterized queries and ORM-based data access to eliminate SQL injection vectors entirely",
      "Content Security Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, and other security headers enforced on all responses",
      "Automated dependency scanning with Software Composition Analysis (SCA) tools integrated into CI/CD pipelines",
      "Static Application Security Testing (SAST) on every pull request before merge",
      "Secrets scanning to prevent accidental credential leaks in source code",
    ],
  },
  {
    id: "auth",
    icon: KeyRound,
    title: "Authentication & Access Control",
    color: "var(--primary)",
    paragraphs: [
      "Access to Argus and its underlying systems follows the principle of least privilege at every layer.",
    ],
    items: [
      "Role-based access control (RBAC) with granular permissions — users only see and do what their role requires",
      "API key management with scoped permissions, automatic expiration policies, and one-click revocation",
      "Secure session management with short-lived tokens, automatic expiry, and forced re-authentication for sensitive operations",
      "Multi-factor authentication (MFA) enforced for all internal systems and available for all customer accounts",
      "Comprehensive audit logging of all authentication events, permission changes, and data access — immutable and tamper-evident",
      "Automated detection of anomalous access patterns with real-time alerting",
    ],
  },
  {
    id: "data",
    icon: Database,
    title: "Data Protection",
    color: "var(--info, #00BBD9)",
    paragraphs: [
      "We treat customer data as sacrosanct. Our data protection program covers classification, encryption, retention, and residency.",
    ],
    items: [
      "Formal data classification framework — all data categorized by sensitivity level with handling requirements enforced programmatically",
      "Encryption at rest (AES-256) and in transit (TLS 1.3) across all storage and communication layers",
      "Automated, encrypted backups with tested restoration procedures and geographically separated backup storage",
      "Data residency controls to ensure threat intelligence data is processed and stored in compliance with jurisdictional requirements",
      "Strict data retention policies with automated, cryptographically verified deletion when data reaches end of lifecycle",
      "Logical tenant isolation ensuring one customer's data is never accessible to another",
    ],
  },
  {
    id: "operations",
    icon: Eye,
    title: "Operational Security",
    color: "var(--primary)",
    paragraphs: [
      "Security operations run around the clock. Our operational practices ensure we can detect, respond, and recover from incidents rapidly.",
    ],
    items: [
      "24/7 monitoring of all production systems with automated anomaly detection and alerting",
      "Documented incident response plan with defined severity levels, escalation paths, and communication protocols",
      "Formal change management process — all production changes are peer-reviewed, tested in staging, and deployed with rollback capability",
      "Mandatory security awareness training for all employees, with specialized training for engineering and operations teams",
      "Background checks conducted on all team members with access to customer data or production systems",
      "Regular tabletop exercises and incident simulations to validate response readiness",
    ],
  },
  {
    id: "compliance",
    icon: Scale,
    title: "Compliance",
    color: "var(--secondary, #8E33FF)",
    paragraphs: [
      "We are committed to meeting and exceeding industry-recognized compliance standards.",
    ],
    items: [
      "Actively working toward SOC 2 Type II certification — our controls are designed and operated to meet Trust Services Criteria for security, availability, and confidentiality",
      "GDPR-aware data handling practices including lawful basis documentation, data subject rights fulfillment, and Data Protection Impact Assessments where applicable",
      "Privacy-by-design principles embedded into product development from requirements through deployment",
      "Regular internal audits against our control framework with findings tracked to remediation",
    ],
  },
  {
    id: "disclosure",
    icon: AlertTriangle,
    title: "Vulnerability Disclosure Program",
    color: "var(--warning, #FFAB00)",
    paragraphs: [
      "We believe that security researchers play a vital role in keeping the internet safe. If you discover a vulnerability in any Argus product or service, we want to hear from you.",
      "Please report security vulnerabilities responsibly through our contact form at /about#contact with the following details:",
    ],
    items: [
      "A clear description of the vulnerability and its potential impact",
      "Detailed steps to reproduce the issue, including any tools or scripts used",
      "Any supporting evidence such as screenshots, logs, or proof-of-concept code",
      "Your preferred method of contact for follow-up communication",
    ],
  },
  {
    id: "third-party",
    icon: Handshake,
    title: "Third-Party Security",
    color: "var(--primary)",
    paragraphs: [
      "We carefully evaluate every vendor and integration that touches customer data or production systems.",
    ],
    items: [
      "Formal vendor security assessment process — third parties are evaluated for security posture, compliance certifications, and data handling practices before onboarding",
      "Minimal data sharing principle — we share only the data strictly necessary for a vendor to perform its function, and never more",
      "Contractual security requirements including data processing agreements, breach notification obligations, and right-to-audit clauses",
      "Ongoing monitoring of critical vendors for security incidents, compliance changes, and service reliability",
    ],
  },
];

/* ─────────────────────── Disclosure promise items ─────────────────────── */

const DISCLOSURE_PROMISES = [
  "We will acknowledge your report within 2 business days",
  "We will provide an initial assessment within 5 business days",
  "We will keep you informed of remediation progress",
  "We will not take legal action against researchers acting in good faith",
  "We will credit researchers who wish to be acknowledged (with your permission)",
];

/* ─────────────────────── Component ─────────────────────── */

export default function SecurityPage() {
  return (
    <>
      {/* ═══════════════════ HERO ═══════════════════ */}
      <section
        style={{
          position: "relative",
          minHeight: "70vh",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          background: "var(--hero-bg)",
          overflow: "hidden",
          padding: "140px 24px 100px",
        }}
      >
        {/* Decorative orb */}
        <div
          style={{
            position: "absolute",
            width: 800,
            height: 800,
            borderRadius: "50%",
            background:
              "radial-gradient(circle, rgba(0,167,111,0.06) 0%, rgba(142,51,255,0.03) 40%, transparent 70%)",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            pointerEvents: "none",
          }}
        />

        {/* Subtle grid */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            backgroundImage:
              "linear-gradient(rgba(0,167,111,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,167,111,0.03) 1px, transparent 1px)",
            backgroundSize: "60px 60px",
            pointerEvents: "none",
          }}
        />

        {/* Bottom fade */}
        <div
          style={{
            position: "absolute",
            bottom: 0,
            left: 0,
            right: 0,
            height: 200,
            background: "linear-gradient(to top, var(--bg), transparent)",
            zIndex: 1,
          }}
        />

        <div
          style={{
            position: "relative",
            zIndex: 10,
            textAlign: "center",
            maxWidth: 800,
          }}
        >
          <AnimateIn delay={0.1}>
            <div
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                padding: "6px 16px",
                borderRadius: 100,
                border: "1px solid rgba(0,167,111,0.2)",
                background: "rgba(0,167,111,0.08)",
                marginBottom: 32,
              }}
            >
              <Shield size={14} style={{ color: "var(--primary)" }} />
              <span
                style={{
                  fontSize: 13,
                  fontWeight: 500,
                  color: "var(--primary-light)",
                }}
              >
                Security practices
              </span>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.2}>
            <h1
              style={{
                fontSize: "clamp(40px, 5.5vw, 64px)",
                fontWeight: 700,
                lineHeight: 1.08,
                letterSpacing: "-0.03em",
                color: "#F4F6F8",
                marginBottom: 24,
              }}
            >
              Security at{" "}
              <span className="gradient-text">Argus</span>
            </h1>
          </AnimateIn>

          <AnimateIn delay={0.35}>
            <p
              style={{
                fontSize: "clamp(16px, 2vw, 20px)",
                lineHeight: 1.6,
                color: "rgba(244,246,248,0.6)",
                maxWidth: 640,
                margin: "0 auto",
              }}
            >
              We build a threat intelligence platform trusted by security teams
              worldwide. That trust starts with how we secure our own house.
              Here&apos;s how we protect your data, our infrastructure, and the
              integrity of every alert we deliver.
            </p>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ LAST UPDATED ═══════════════════ */}
      <section style={{ padding: "48px 24px 0", background: "var(--bg)" }}>
        <div style={{ maxWidth: 800, margin: "0 auto" }}>
          <AnimateIn delay={0.1}>
            <div
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                padding: "8px 16px",
                borderRadius: 8,
                background: "var(--bg-alt)",
                border: "1px solid var(--border)",
                color: "var(--text-muted)",
                fontSize: 13,
                fontWeight: 500,
              }}
            >
              <Clock size={14} />
              Last updated: March 11, 2026
            </div>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ SECTIONS ═══════════════════ */}
      {SECTIONS.map((section, idx) => (
        <section
          key={section.id}
          id={section.id}
          style={{
            padding: "80px 24px",
            background: idx % 2 === 0 ? "var(--bg)" : "var(--bg-alt)",
          }}
        >
          <div style={{ maxWidth: 800, margin: "0 auto" }}>
            <AnimateIn delay={0.1}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 14,
                  marginBottom: 24,
                }}
              >
                <div
                  style={{
                    width: 44,
                    height: 44,
                    borderRadius: 10,
                    background: `color-mix(in srgb, ${section.color} 12%, transparent)`,
                    border: `1px solid color-mix(in srgb, ${section.color} 20%, transparent)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}
                >
                  <section.icon size={22} style={{ color: section.color }} />
                </div>
                <h2
                  style={{
                    fontSize: "clamp(24px, 3.5vw, 32px)",
                    fontWeight: 700,
                    color: "var(--text)",
                    letterSpacing: "-0.02em",
                    lineHeight: 1.2,
                  }}
                >
                  {section.title}
                </h2>
              </div>
            </AnimateIn>

            {section.paragraphs.map((p, i) => (
              <AnimateIn key={i} delay={0.15 + i * 0.05}>
                <p
                  style={{
                    fontSize: 16,
                    lineHeight: 1.75,
                    color: "var(--text-muted)",
                    marginBottom: 16,
                  }}
                >
                  {p}
                </p>
              </AnimateIn>
            ))}

            {section.items && (
              <AnimateIn delay={0.25}>
                <ul
                  style={{
                    listStyle: "none",
                    padding: 0,
                    margin: "24px 0 0",
                    display: "flex",
                    flexDirection: "column",
                    gap: 14,
                  }}
                >
                  {section.items.map((item, i) => (
                    <li
                      key={i}
                      style={{
                        display: "flex",
                        alignItems: "flex-start",
                        gap: 12,
                        fontSize: 15,
                        lineHeight: 1.65,
                        color: "var(--text-muted)",
                      }}
                    >
                      <CheckCircle2
                        size={18}
                        style={{
                          color: section.color,
                          flexShrink: 0,
                          marginTop: 3,
                        }}
                      />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </AnimateIn>
            )}

            {/* Extra content for disclosure section */}
            {section.id === "disclosure" && (
              <>
                <AnimateIn delay={0.35}>
                  <div
                    style={{
                      marginTop: 32,
                      padding: 24,
                      borderRadius: 12,
                      background: "var(--bg)",
                      border: "1px solid var(--border)",
                    }}
                  >
                    <h3
                      style={{
                        fontSize: 17,
                        fontWeight: 600,
                        color: "var(--text)",
                        marginBottom: 16,
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                      }}
                    >
                      <FileKey size={18} style={{ color: "var(--primary)" }} />
                      Our commitment to researchers
                    </h3>
                    <ul
                      style={{
                        listStyle: "none",
                        padding: 0,
                        margin: 0,
                        display: "flex",
                        flexDirection: "column",
                        gap: 10,
                      }}
                    >
                      {DISCLOSURE_PROMISES.map((promise, i) => (
                        <li
                          key={i}
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            gap: 10,
                            fontSize: 14,
                            lineHeight: 1.6,
                            color: "var(--text-muted)",
                          }}
                        >
                          <CheckCircle2
                            size={16}
                            style={{
                              color: "var(--primary)",
                              flexShrink: 0,
                              marginTop: 2,
                            }}
                          />
                          <span>{promise}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </AnimateIn>

                <AnimateIn delay={0.4}>
                  <p
                    style={{
                      fontSize: 14,
                      lineHeight: 1.6,
                      color: "var(--text-muted)",
                      marginTop: 20,
                      fontStyle: "italic",
                    }}
                  >
                    Please do not publicly disclose vulnerabilities before we
                    have had a reasonable opportunity to investigate and address
                    them. We ask for a minimum of 90 days from initial report.
                  </p>
                </AnimateIn>
              </>
            )}
          </div>
        </section>
      ))}

      {/* ═══════════════════ CONTACT ═══════════════════ */}
      <section
        style={{
          padding: "80px 24px 120px",
          background: "var(--bg)",
        }}
      >
        <div style={{ maxWidth: 800, margin: "0 auto" }}>
          <AnimateIn delay={0.1}>
            <div
              style={{
                padding: 40,
                borderRadius: 16,
                background:
                  "linear-gradient(135deg, rgba(0,167,111,0.06) 0%, rgba(142,51,255,0.04) 100%)",
                border: "1px solid rgba(0,167,111,0.15)",
                textAlign: "center",
              }}
            >
              <div
                style={{
                  width: 56,
                  height: 56,
                  borderRadius: 14,
                  background: "rgba(0,167,111,0.1)",
                  border: "1px solid rgba(0,167,111,0.2)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  margin: "0 auto 24px",
                }}
              >
                <Mail size={26} style={{ color: "var(--primary)" }} />
              </div>

              <h2
                style={{
                  fontSize: "clamp(24px, 3.5vw, 32px)",
                  fontWeight: 700,
                  color: "var(--text)",
                  letterSpacing: "-0.02em",
                  marginBottom: 12,
                }}
              >
                Security questions?
              </h2>

              <p
                style={{
                  fontSize: 16,
                  lineHeight: 1.7,
                  color: "var(--text-muted)",
                  maxWidth: 540,
                  margin: "0 auto 28px",
                }}
              >
                Whether you have questions about our security practices, need to
                report a vulnerability, or want to discuss your organization&apos;s
                security requirements, we&apos;re here to help.
              </p>

              <a
                href="/about#contact"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "14px 32px",
                  borderRadius: 10,
                  background: "var(--primary)",
                  color: "#fff",
                  fontSize: 15,
                  fontWeight: 600,
                  textDecoration: "none",
                  transition: "background 0.2s ease",
                }}
                onMouseEnter={(e) =>
                  (e.currentTarget.style.background = "var(--primary-dark)")
                }
                onMouseLeave={(e) =>
                  (e.currentTarget.style.background = "var(--primary)")
                }
              >
                <Lock size={16} />
                Contact us
              </a>

              <div
                style={{
                  display: "flex",
                  justifyContent: "center",
                  gap: 32,
                  marginTop: 32,
                  flexWrap: "wrap",
                }}
              >
                {[
                  { icon: Globe, label: "argusai.xyz" },
                  { icon: Users, label: "Argus" },
                  { icon: Shield, label: "Argus Platform" },
                ].map((item) => (
                  <div
                    key={item.label}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      fontSize: 13,
                      color: "var(--text-muted)",
                    }}
                  >
                    <item.icon size={14} style={{ opacity: 0.6 }} />
                    {item.label}
                  </div>
                ))}
              </div>
            </div>
          </AnimateIn>
        </div>
      </section>
    </>
  );
}
