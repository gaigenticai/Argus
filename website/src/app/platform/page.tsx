"use client";

import Link from "next/link";
import { AnimateIn } from "@/components/animate-in";
import {
  Layers,
  Brain,
  Zap,
  Database,
  Globe,
  Bug,
  Shield,
  Radar,
  Network,
  Workflow,
  Fish,
  Cloud,
  ArrowRight,
  ArrowDown,
  Server,
  Container,
  Lock,
  KeyRound,
  ScrollText,
  HardDrive,
  CheckCircle2,
  ChevronRight,
} from "lucide-react";

/* ─── DATA ─── */

const DATA_LAYER = [
  { icon: Globe, label: "Threat Feeds", desc: "30+ global intelligence sources ingested continuously" },
  { icon: Radar, label: "Dark Web Crawlers", desc: "Forums, paste sites, and hidden marketplaces" },
  { icon: Bug, label: "Vulnerability Scanners", desc: "CVE detection across your entire attack surface" },
];

const INTELLIGENCE_LAYER = [
  { icon: Brain, label: "AI Triage", desc: "Autonomous classification, severity scoring, and prioritization" },
  { icon: Shield, label: "IOC Extraction", desc: "IPs, domains, hashes, and CVEs extracted automatically" },
  { icon: Network, label: "Correlation Engine", desc: "Cross-reference indicators across all data sources" },
];

const ACTION_LAYER = [
  { icon: Zap, label: "Alerts", desc: "Real-time notifications with full context and reasoning" },
  { icon: Workflow, label: "SOAR Workflows", desc: "Automated response playbooks triggered instantly" },
  { icon: ScrollText, label: "Reports", desc: "Executive and technical reports generated on demand" },
];

const INTEGRATIONS = [
  {
    name: "OpenCTI",
    category: "Threat Intelligence",
    desc: "Structured threat intelligence management with STIX/TAXII support and relationship mapping.",
    license: "Apache 2.0",
    color: "var(--secondary)",
  },
  {
    name: "Wazuh",
    category: "SIEM / EDR",
    desc: "Host-based intrusion detection, log analysis, and endpoint detection and response.",
    license: "GPL v2",
    color: "var(--info)",
  },
  {
    name: "Nuclei",
    category: "Vulnerability Scanner",
    desc: "Template-based scanning engine for fast, configurable vulnerability detection.",
    license: "MIT",
    color: "var(--primary)",
  },
  {
    name: "YARA",
    category: "Malware Detection",
    desc: "Pattern matching rules for identifying and classifying malware samples.",
    license: "BSD 3-Clause",
    color: "var(--error)",
  },
  {
    name: "Sigma",
    category: "Detection Rules",
    desc: "Generic signature format for SIEM systems. Write once, deploy everywhere.",
    license: "LGPL 2.1",
    color: "var(--warning)",
  },
  {
    name: "SpiderFoot",
    category: "OSINT",
    desc: "Automated open-source intelligence collection across 200+ data sources.",
    license: "MIT",
    color: "var(--success)",
  },
  {
    name: "Suricata",
    category: "Network IDS",
    desc: "High-performance network intrusion detection, prevention, and security monitoring.",
    license: "GPL v2",
    color: "var(--info)",
  },
  {
    name: "Shuffle",
    category: "SOAR",
    desc: "Security orchestration, automation, and response. Connect tools and automate workflows.",
    license: "AGPL v3",
    color: "var(--secondary)",
  },
  {
    name: "GoPhish",
    category: "Phishing Simulation",
    desc: "Launch and track phishing simulations to test organizational awareness.",
    license: "MIT",
    color: "var(--warning)",
  },
  {
    name: "Prowler",
    category: "Cloud Security",
    desc: "AWS, Azure, and GCP security assessments, auditing, and compliance scanning.",
    license: "Apache 2.0",
    color: "var(--primary)",
  },
];

const DEPLOYMENT_FEATURES = [
  { icon: Cloud, title: "Railway", desc: "One-click deploy to Railway with managed infrastructure" },
  { icon: Container, title: "Docker", desc: "Full Docker Compose stack — spin up in minutes" },
  { icon: Server, title: "Self-Hosted", desc: "Deploy on your own infrastructure with full control" },
];

const SECURITY_FEATURES = [
  { icon: Lock, title: "Role-Based Access Control", desc: "Granular permissions with predefined roles for analysts, managers, and administrators." },
  { icon: KeyRound, title: "API Key Management", desc: "Scoped API keys with rate limiting, expiry, and per-key audit trails." },
  { icon: ScrollText, title: "Audit Logging", desc: "Every action logged with timestamps, user context, and change history." },
  { icon: HardDrive, title: "Encrypted Storage", desc: "All data encrypted at rest and in transit. Secrets managed via environment isolation." },
];

/* ─── COMPONENT ─── */

export default function PlatformPage() {
  return (
    <>
      {/* ═══════════════════ HERO ═══════════════════ */}
      <section
        style={{
          padding: "160px 24px 100px",
          background: "var(--hero-bg)",
          position: "relative",
          overflow: "hidden",
          textAlign: "center",
        }}
      >
        {/* Decorative orbs */}
        <div
          style={{
            position: "absolute",
            width: 700,
            height: 700,
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(0,167,111,0.07) 0%, transparent 70%)",
            top: -300,
            left: "50%",
            transform: "translateX(-50%)",
            pointerEvents: "none",
          }}
        />
        <div
          style={{
            position: "absolute",
            width: 500,
            height: 500,
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(142,51,255,0.05) 0%, transparent 70%)",
            bottom: -200,
            right: -100,
            pointerEvents: "none",
          }}
        />

        <div style={{ maxWidth: 800, margin: "0 auto", position: "relative", zIndex: 1 }}>
          <AnimateIn delay={0.1}>
            <div
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                padding: "6px 16px",
                borderRadius: 100,
                border: "1px solid rgba(142,51,255,0.2)",
                background: "rgba(142,51,255,0.08)",
                marginBottom: 32,
              }}
            >
              <Layers size={14} style={{ color: "var(--secondary)" }} />
              <span style={{ fontSize: 13, fontWeight: 500, color: "var(--secondary-light)" }}>
                Platform Architecture
              </span>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.2}>
            <h1
              style={{
                fontSize: "clamp(40px, 6vw, 68px)",
                fontWeight: 700,
                lineHeight: 1.08,
                letterSpacing: "-0.03em",
                color: "#F4F6F8",
                marginBottom: 24,
              }}
            >
              The Platform
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
              A unified architecture that transforms raw threat data into actionable intelligence
              — from ingestion to automated response — in a single, cohesive platform.
            </p>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ ARCHITECTURE ═══════════════════ */}
      <section style={{ padding: "120px 0", background: "var(--bg)" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 24px" }}>
          <AnimateIn>
            <div style={{ textAlign: "center", marginBottom: 80 }}>
              <p
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  color: "var(--primary)",
                  marginBottom: 16,
                }}
              >
                How it works
              </p>
              <h2
                style={{
                  fontSize: "clamp(32px, 4vw, 48px)",
                  fontWeight: 700,
                  lineHeight: 1.15,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                  marginBottom: 16,
                }}
              >
                Three layers. One mission.
              </h2>
              <p
                style={{
                  fontSize: 17,
                  lineHeight: 1.6,
                  color: "var(--text-secondary)",
                  maxWidth: 560,
                  margin: "0 auto",
                }}
              >
                Every threat passes through a structured pipeline — collected, analyzed, and acted
                upon without manual intervention.
              </p>
            </div>
          </AnimateIn>

          {/* Architecture flow */}
          <div style={{ display: "flex", flexDirection: "column", gap: 0, alignItems: "center" }}>
            {/* Data Layer */}
            <AnimateIn delay={0.1}>
              <div style={{ width: "100%", maxWidth: 900 }}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    marginBottom: 20,
                    justifyContent: "center",
                  }}
                >
                  <div
                    style={{
                      width: 36,
                      height: 36,
                      borderRadius: 10,
                      background: "rgba(0,187,217,0.1)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <Database size={18} style={{ color: "var(--info)" }} />
                  </div>
                  <h3 style={{ fontSize: 20, fontWeight: 700, color: "var(--text)" }}>
                    Data Layer
                  </h3>
                </div>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(3, 1fr)",
                    gap: 16,
                  }}
                  className="arch-grid"
                >
                  {DATA_LAYER.map((item) => {
                    const Icon = item.icon;
                    return (
                      <div
                        key={item.label}
                        style={{
                          padding: 24,
                          borderRadius: 14,
                          border: "1px solid var(--border)",
                          background: "var(--bg-card)",
                          transition: "all 0.3s",
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.borderColor = "var(--info)";
                          e.currentTarget.style.transform = "translateY(-2px)";
                          e.currentTarget.style.boxShadow = "0 8px 32px rgba(0,187,217,0.08)";
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.borderColor = "var(--border)";
                          e.currentTarget.style.transform = "translateY(0)";
                          e.currentTarget.style.boxShadow = "none";
                        }}
                      >
                        <Icon size={20} style={{ color: "var(--info)", marginBottom: 12 }} />
                        <div style={{ fontSize: 15, fontWeight: 600, color: "var(--text)", marginBottom: 6 }}>
                          {item.label}
                        </div>
                        <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-muted)" }}>
                          {item.desc}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </AnimateIn>

            {/* Arrow connector */}
            <AnimateIn delay={0.2}>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  padding: "20px 0",
                }}
              >
                <div
                  style={{
                    width: 2,
                    height: 40,
                    background: "linear-gradient(to bottom, var(--info), var(--secondary))",
                    borderRadius: 1,
                  }}
                />
                <ArrowDown size={20} style={{ color: "var(--secondary)", marginTop: -4 }} />
              </div>
            </AnimateIn>

            {/* Intelligence Layer */}
            <AnimateIn delay={0.3}>
              <div style={{ width: "100%", maxWidth: 900 }}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    marginBottom: 20,
                    justifyContent: "center",
                  }}
                >
                  <div
                    style={{
                      width: 36,
                      height: 36,
                      borderRadius: 10,
                      background: "rgba(142,51,255,0.1)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <Brain size={18} style={{ color: "var(--secondary)" }} />
                  </div>
                  <h3 style={{ fontSize: 20, fontWeight: 700, color: "var(--text)" }}>
                    Intelligence Layer
                  </h3>
                </div>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(3, 1fr)",
                    gap: 16,
                  }}
                  className="arch-grid"
                >
                  {INTELLIGENCE_LAYER.map((item) => {
                    const Icon = item.icon;
                    return (
                      <div
                        key={item.label}
                        style={{
                          padding: 24,
                          borderRadius: 14,
                          border: "1px solid var(--border)",
                          background: "var(--bg-card)",
                          transition: "all 0.3s",
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.borderColor = "var(--secondary)";
                          e.currentTarget.style.transform = "translateY(-2px)";
                          e.currentTarget.style.boxShadow = "0 8px 32px rgba(142,51,255,0.08)";
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.borderColor = "var(--border)";
                          e.currentTarget.style.transform = "translateY(0)";
                          e.currentTarget.style.boxShadow = "none";
                        }}
                      >
                        <Icon size={20} style={{ color: "var(--secondary)", marginBottom: 12 }} />
                        <div style={{ fontSize: 15, fontWeight: 600, color: "var(--text)", marginBottom: 6 }}>
                          {item.label}
                        </div>
                        <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-muted)" }}>
                          {item.desc}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </AnimateIn>

            {/* Arrow connector */}
            <AnimateIn delay={0.4}>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  padding: "20px 0",
                }}
              >
                <div
                  style={{
                    width: 2,
                    height: 40,
                    background: "linear-gradient(to bottom, var(--secondary), var(--primary))",
                    borderRadius: 1,
                  }}
                />
                <ArrowDown size={20} style={{ color: "var(--primary)", marginTop: -4 }} />
              </div>
            </AnimateIn>

            {/* Action Layer */}
            <AnimateIn delay={0.5}>
              <div style={{ width: "100%", maxWidth: 900 }}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    marginBottom: 20,
                    justifyContent: "center",
                  }}
                >
                  <div
                    style={{
                      width: 36,
                      height: 36,
                      borderRadius: 10,
                      background: "rgba(0,167,111,0.1)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <Zap size={18} style={{ color: "var(--primary)" }} />
                  </div>
                  <h3 style={{ fontSize: 20, fontWeight: 700, color: "var(--text)" }}>
                    Action Layer
                  </h3>
                </div>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(3, 1fr)",
                    gap: 16,
                  }}
                  className="arch-grid"
                >
                  {ACTION_LAYER.map((item) => {
                    const Icon = item.icon;
                    return (
                      <div
                        key={item.label}
                        style={{
                          padding: 24,
                          borderRadius: 14,
                          border: "1px solid var(--border)",
                          background: "var(--bg-card)",
                          transition: "all 0.3s",
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.borderColor = "var(--primary)";
                          e.currentTarget.style.transform = "translateY(-2px)";
                          e.currentTarget.style.boxShadow = "0 8px 32px rgba(0,167,111,0.08)";
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.borderColor = "var(--border)";
                          e.currentTarget.style.transform = "translateY(0)";
                          e.currentTarget.style.boxShadow = "none";
                        }}
                      >
                        <Icon size={20} style={{ color: "var(--primary)", marginBottom: 12 }} />
                        <div style={{ fontSize: 15, fontWeight: 600, color: "var(--text)", marginBottom: 6 }}>
                          {item.label}
                        </div>
                        <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-muted)" }}>
                          {item.desc}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </AnimateIn>
          </div>
        </div>
      </section>

      {/* ═══════════════════ INTEGRATION ECOSYSTEM ═══════════════════ */}
      <section
        style={{
          padding: "120px 0",
          background: "var(--bg-alt)",
          borderTop: "1px solid var(--border)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 24px" }}>
          <AnimateIn>
            <div style={{ textAlign: "center", marginBottom: 80 }}>
              <p
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  color: "var(--primary)",
                  marginBottom: 16,
                }}
              >
                Integrations
              </p>
              <h2
                style={{
                  fontSize: "clamp(32px, 4vw, 48px)",
                  fontWeight: 700,
                  lineHeight: 1.15,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                  marginBottom: 16,
                }}
              >
                10 best-in-class tools. One platform.
              </h2>
              <p
                style={{
                  fontSize: 17,
                  lineHeight: 1.6,
                  color: "var(--text-secondary)",
                  maxWidth: 600,
                  margin: "0 auto",
                }}
              >
                Every tool is open-source, battle-tested, and deeply integrated — not bolted on.
                No vendor lock-in, full transparency.
              </p>
            </div>
          </AnimateIn>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(2, 1fr)",
              gap: 20,
            }}
            className="integration-grid"
          >
            {INTEGRATIONS.map((tool, i) => (
              <AnimateIn key={tool.name} delay={i * 0.05}>
                <div
                  style={{
                    padding: 28,
                    borderRadius: 16,
                    border: "1px solid var(--border)",
                    background: "var(--bg-card)",
                    transition: "all 0.35s",
                    cursor: "default",
                    height: "100%",
                    display: "flex",
                    flexDirection: "column",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = tool.color;
                    e.currentTarget.style.boxShadow = `0 0 40px ${tool.color}10, 0 16px 48px rgba(0,0,0,0.08)`;
                    e.currentTarget.style.transform = "translateY(-3px)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = "var(--border)";
                    e.currentTarget.style.boxShadow = "none";
                    e.currentTarget.style.transform = "translateY(0)";
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      marginBottom: 14,
                      flexWrap: "wrap",
                      gap: 8,
                    }}
                  >
                    <h3 style={{ fontSize: 18, fontWeight: 700, color: "var(--text)" }}>
                      {tool.name}
                    </h3>
                    <span
                      style={{
                        fontSize: 11,
                        fontWeight: 600,
                        padding: "4px 10px",
                        borderRadius: 100,
                        background: `${tool.color}12`,
                        color: tool.color,
                        textTransform: "uppercase",
                        letterSpacing: "0.04em",
                      }}
                    >
                      {tool.category}
                    </span>
                  </div>
                  <p
                    style={{
                      fontSize: 14,
                      lineHeight: 1.7,
                      color: "var(--text-secondary)",
                      marginBottom: 16,
                      flex: 1,
                    }}
                  >
                    {tool.desc}
                  </p>
                  <div
                    style={{
                      fontSize: 12,
                      color: "var(--text-muted)",
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                    }}
                  >
                    <CheckCircle2 size={13} style={{ color: "var(--success)" }} />
                    Open Source &middot; {tool.license}
                  </div>
                </div>
              </AnimateIn>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════════════ DEPLOYMENT ═══════════════════ */}
      <section style={{ padding: "120px 0", background: "var(--bg)" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 24px" }}>
          <AnimateIn>
            <div style={{ textAlign: "center", marginBottom: 64 }}>
              <p
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  color: "var(--primary)",
                  marginBottom: 16,
                }}
              >
                Deployment
              </p>
              <h2
                style={{
                  fontSize: "clamp(32px, 4vw, 48px)",
                  fontWeight: 700,
                  lineHeight: 1.15,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                  marginBottom: 16,
                }}
              >
                Cloud-native. Deploys anywhere.
              </h2>
              <p
                style={{
                  fontSize: 17,
                  lineHeight: 1.6,
                  color: "var(--text-secondary)",
                  maxWidth: 560,
                  margin: "0 auto",
                }}
              >
                From a single Docker command to fully managed cloud — run Argus wherever your
                security requirements demand.
              </p>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.15}>
            <div
              style={{
                borderRadius: 20,
                border: "1px solid var(--border)",
                background: "#0A0E14",
                padding: "48px 40px",
                position: "relative",
                overflow: "hidden",
              }}
            >
              {/* Grid decoration */}
              <div
                style={{
                  position: "absolute",
                  inset: 0,
                  backgroundImage:
                    "linear-gradient(rgba(0,167,111,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,167,111,0.03) 1px, transparent 1px)",
                  backgroundSize: "48px 48px",
                  pointerEvents: "none",
                }}
              />

              <div
                style={{
                  position: "relative",
                  zIndex: 1,
                  display: "grid",
                  gridTemplateColumns: "repeat(3, 1fr)",
                  gap: 32,
                }}
                className="deploy-grid"
              >
                {DEPLOYMENT_FEATURES.map((feat) => {
                  const Icon = feat.icon;
                  return (
                    <div key={feat.title} style={{ textAlign: "center" }}>
                      <div
                        style={{
                          width: 56,
                          height: 56,
                          borderRadius: 14,
                          background: "rgba(0,167,111,0.1)",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          margin: "0 auto 20px",
                          border: "1px solid rgba(0,167,111,0.15)",
                        }}
                      >
                        <Icon size={24} style={{ color: "var(--primary-light)" }} />
                      </div>
                      <h3
                        style={{
                          fontSize: 18,
                          fontWeight: 600,
                          color: "#F4F6F8",
                          marginBottom: 8,
                        }}
                      >
                        {feat.title}
                      </h3>
                      <p style={{ fontSize: 14, lineHeight: 1.6, color: "rgba(244,246,248,0.5)" }}>
                        {feat.desc}
                      </p>
                    </div>
                  );
                })}
              </div>

              {/* Bottom features row */}
              <div
                style={{
                  position: "relative",
                  zIndex: 1,
                  display: "flex",
                  justifyContent: "center",
                  gap: 32,
                  marginTop: 40,
                  paddingTop: 32,
                  borderTop: "1px solid rgba(255,255,255,0.06)",
                  flexWrap: "wrap",
                }}
              >
                {[
                  "Container-first architecture",
                  "Environment-based configuration",
                  "Zero-downtime upgrades",
                  "Horizontal scaling",
                ].map((feature) => (
                  <div
                    key={feature}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      fontSize: 13,
                      color: "rgba(244,246,248,0.5)",
                    }}
                  >
                    <CheckCircle2 size={14} style={{ color: "var(--primary)" }} />
                    {feature}
                  </div>
                ))}
              </div>
            </div>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ SECURITY & COMPLIANCE ═══════════════════ */}
      <section
        style={{
          padding: "120px 0",
          background: "var(--bg-alt)",
          borderTop: "1px solid var(--border)",
        }}
      >
        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 24px" }}>
          <AnimateIn>
            <div style={{ textAlign: "center", marginBottom: 80 }}>
              <p
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  color: "var(--primary)",
                  marginBottom: 16,
                }}
              >
                Security & Compliance
              </p>
              <h2
                style={{
                  fontSize: "clamp(32px, 4vw, 48px)",
                  fontWeight: 700,
                  lineHeight: 1.15,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                  marginBottom: 16,
                }}
              >
                Built secure from day one
              </h2>
              <p
                style={{
                  fontSize: 17,
                  lineHeight: 1.6,
                  color: "var(--text-secondary)",
                  maxWidth: 560,
                  margin: "0 auto",
                }}
              >
                Enterprise-grade security controls baked into every layer of the platform.
              </p>
            </div>
          </AnimateIn>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(2, 1fr)",
              gap: 24,
            }}
            className="security-grid"
          >
            {SECURITY_FEATURES.map((feat, i) => {
              const Icon = feat.icon;
              return (
                <AnimateIn key={feat.title} delay={i * 0.08}>
                  <div
                    style={{
                      padding: 32,
                      borderRadius: 16,
                      border: "1px solid var(--border)",
                      background: "var(--bg-card)",
                      transition: "all 0.35s",
                      height: "100%",
                      display: "flex",
                      gap: 20,
                      alignItems: "flex-start",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = "var(--primary)";
                      e.currentTarget.style.transform = "translateY(-2px)";
                      e.currentTarget.style.boxShadow = "0 8px 32px rgba(0,167,111,0.06)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = "var(--border)";
                      e.currentTarget.style.transform = "translateY(0)";
                      e.currentTarget.style.boxShadow = "none";
                    }}
                  >
                    <div
                      style={{
                        width: 48,
                        height: 48,
                        borderRadius: 12,
                        background: "rgba(0,167,111,0.08)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        flexShrink: 0,
                      }}
                    >
                      <Icon size={22} style={{ color: "var(--primary)" }} />
                    </div>
                    <div>
                      <h3
                        style={{
                          fontSize: 17,
                          fontWeight: 600,
                          color: "var(--text)",
                          marginBottom: 8,
                        }}
                      >
                        {feat.title}
                      </h3>
                      <p style={{ fontSize: 14, lineHeight: 1.7, color: "var(--text-secondary)" }}>
                        {feat.desc}
                      </p>
                    </div>
                  </div>
                </AnimateIn>
              );
            })}
          </div>
        </div>
      </section>

      {/* ═══════════════════ CTA ═══════════════════ */}
      <section
        style={{
          padding: "120px 0",
          background: "var(--bg)",
          position: "relative",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            position: "absolute",
            width: 800,
            height: 800,
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(0,167,111,0.06) 0%, transparent 70%)",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            pointerEvents: "none",
          }}
        />

        <div
          style={{
            maxWidth: 720,
            margin: "0 auto",
            padding: "0 24px",
            textAlign: "center",
            position: "relative",
          }}
        >
          <AnimateIn>
            <h2
              style={{
                fontSize: "clamp(32px, 4vw, 48px)",
                fontWeight: 700,
                lineHeight: 1.15,
                letterSpacing: "-0.02em",
                color: "var(--text)",
                marginBottom: 20,
              }}
            >
              Deploy Argus today
            </h2>
            <p
              style={{
                fontSize: 17,
                lineHeight: 1.6,
                color: "var(--text-secondary)",
                marginBottom: 40,
              }}
            >
              Get full-spectrum threat intelligence running in minutes.
              Open source, self-hostable, and ready for production.
            </p>
            <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
              <Link
                href="https://argusai.xyz"
                target="_blank"
                style={{
                  height: 52,
                  padding: "0 32px",
                  borderRadius: 12,
                  background: "var(--primary)",
                  color: "#fff",
                  fontSize: 15,
                  fontWeight: 600,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 8,
                  textDecoration: "none",
                  transition: "all 0.25s",
                }}
              >
                Start monitoring
                <ArrowRight size={16} />
              </Link>
              <Link
                href="/pricing"
                style={{
                  height: 52,
                  padding: "0 32px",
                  borderRadius: 12,
                  border: "1px solid var(--border)",
                  color: "var(--text)",
                  fontSize: 15,
                  fontWeight: 600,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 8,
                  textDecoration: "none",
                  background: "transparent",
                  transition: "all 0.25s",
                }}
              >
                View pricing
                <ChevronRight size={16} />
              </Link>
            </div>
          </AnimateIn>
        </div>
      </section>

      <style>{`
        @media (max-width: 768px) {
          .arch-grid { grid-template-columns: 1fr !important; }
          .integration-grid { grid-template-columns: 1fr !important; }
          .deploy-grid { grid-template-columns: 1fr !important; }
          .security-grid { grid-template-columns: 1fr !important; }
        }
        @media (min-width: 769px) and (max-width: 1024px) {
          .arch-grid { grid-template-columns: repeat(3, 1fr) !important; }
          .integration-grid { grid-template-columns: 1fr !important; }
          .deploy-grid { grid-template-columns: repeat(3, 1fr) !important; }
          .security-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </>
  );
}
