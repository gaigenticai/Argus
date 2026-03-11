"use client";

import Link from "next/link";
import { WorldMap } from "@/components/world-map";
import { AnimateIn } from "@/components/animate-in";
import {
  Shield,
  Brain,
  Radar,
  Eye,
  Zap,
  Lock,
  Globe,
  ArrowRight,
  ChevronRight,
  Activity,
  Search,
  Target,
  Layers,
  Cpu,
} from "lucide-react";

const STATS = [
  { value: "32K+", label: "Threat indicators tracked" },
  { value: "10+", label: "Integrated security tools" },
  { value: "24/7", label: "Autonomous monitoring" },
  { value: "<5min", label: "Average triage time" },
];

const CAPABILITIES = [
  {
    icon: Globe,
    title: "Global Threat Map",
    desc: "Real-time visualization of threats across every continent. Track ransomware campaigns, C2 servers, phishing infrastructure, and exploit activity as they emerge.",
    color: "var(--primary)",
  },
  {
    icon: Brain,
    title: "Agentic AI Triage",
    desc: "Autonomous AI agents analyze, correlate, and prioritize threats without human intervention. From raw feed to actionable alert in minutes.",
    color: "var(--secondary)",
  },
  {
    icon: Eye,
    title: "Dark Web Intelligence",
    desc: "Monitor underground forums, paste sites, and hidden markets for mentions of your organization, executives, and assets.",
    color: "var(--warning)",
  },
  {
    icon: Layers,
    title: "Unified Security Stack",
    desc: "OpenCTI, Wazuh, Nuclei, YARA, Sigma, SpiderFoot, Suricata, Shuffle, GoPhish, and Prowler — all in one platform.",
    color: "var(--info)",
  },
  {
    icon: Zap,
    title: "Automated Response",
    desc: "SOAR workflows trigger instantly on critical detections. Block IPs, isolate endpoints, notify teams — zero manual steps required.",
    color: "var(--error)",
  },
  {
    icon: Search,
    title: "IOC Intelligence",
    desc: "Automatic extraction of indicators from every feed. Cross-reference IPs, domains, hashes, and CVEs against your entire attack surface.",
    color: "var(--success)",
  },
];

const TRUST_LOGOS = [
  "STIX/TAXII",
  "MITRE ATT&CK",
  "CVE Database",
  "Shodan",
  "GreyNoise",
  "AbuseIPDB",
  "AlienVault OTX",
];

export default function Home() {
  return (
    <>
      {/* ═══════════════════ HERO ═══════════════════ */}
      <section
        style={{
          position: "relative",
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          background: "var(--hero-bg)",
          overflow: "hidden",
        }}
      >
        {/* World map canvas */}
        <WorldMap />

        {/* Radial gradient overlay */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            background:
              "radial-gradient(ellipse 80% 60% at 50% 40%, transparent 0%, rgba(10,14,20,0.6) 60%, rgba(10,14,20,0.95) 100%)",
            zIndex: 1,
          }}
        />

        {/* Top gradient fade */}
        <div
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            height: 200,
            background: "linear-gradient(to bottom, rgba(10,14,20,0.8), transparent)",
            zIndex: 1,
          }}
        />

        {/* Bottom gradient fade */}
        <div
          style={{
            position: "absolute",
            bottom: 0,
            left: 0,
            right: 0,
            height: 300,
            background: "linear-gradient(to top, rgba(10,14,20,1), transparent)",
            zIndex: 1,
          }}
        />

        {/* Scan line effect */}
        <div
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            height: 2,
            background: "linear-gradient(90deg, transparent, var(--primary), transparent)",
            opacity: 0.3,
            animation: "scan-sweep 8s linear infinite",
            zIndex: 2,
          }}
        />

        {/* Content */}
        <div
          style={{
            position: "relative",
            zIndex: 10,
            textAlign: "center",
            padding: "0 24px",
            maxWidth: 900,
          }}
        >
          {/* Badge */}
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
              <Activity size={14} style={{ color: "var(--primary)" }} />
              <span style={{ fontSize: 13, fontWeight: 500, color: "var(--primary-light)" }}>
                Real-time threat intelligence
              </span>
            </div>
          </AnimateIn>

          {/* Headline */}
          <AnimateIn delay={0.2}>
            <h1
              style={{
                fontSize: "clamp(40px, 6vw, 72px)",
                fontWeight: 700,
                lineHeight: 1.08,
                letterSpacing: "-0.03em",
                color: "#F4F6F8",
                marginBottom: 24,
              }}
            >
              See every threat.
              <br />
              <span className="gradient-text">Respond before impact.</span>
            </h1>
          </AnimateIn>

          {/* Subheadline */}
          <AnimateIn delay={0.35}>
            <p
              style={{
                fontSize: "clamp(16px, 2vw, 20px)",
                lineHeight: 1.6,
                color: "rgba(244,246,248,0.6)",
                maxWidth: 640,
                margin: "0 auto 40px",
              }}
            >
              Argus unifies real-time global monitoring, agentic AI triage, and 10+
              world-class security tools into a single intelligence platform.
            </p>
          </AnimateIn>

          {/* CTAs */}
          <AnimateIn delay={0.45}>
            <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
              <Link
                href="https://app.argusai.xyz"
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
                href="/features"
                style={{
                  height: 52,
                  padding: "0 32px",
                  borderRadius: 12,
                  background: "rgba(255,255,255,0.06)",
                  color: "rgba(244,246,248,0.8)",
                  fontSize: 15,
                  fontWeight: 600,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 8,
                  textDecoration: "none",
                  border: "1px solid rgba(255,255,255,0.08)",
                  transition: "all 0.25s",
                }}
              >
                Explore features
              </Link>
            </div>
          </AnimateIn>
        </div>

        {/* Stats bar */}
        <div
          style={{
            position: "absolute",
            bottom: 40,
            left: 0,
            right: 0,
            zIndex: 10,
            display: "flex",
            justifyContent: "center",
            gap: 48,
            flexWrap: "wrap",
            padding: "0 24px",
          }}
          className="hero-stats"
        >
          {STATS.map((stat, i) => (
            <AnimateIn key={stat.label} delay={0.6 + i * 0.1}>
              <div style={{ textAlign: "center" }}>
                <div
                  style={{
                    fontSize: 28,
                    fontWeight: 700,
                    color: "var(--primary-light)",
                    letterSpacing: "-0.02em",
                  }}
                >
                  {stat.value}
                </div>
                <div style={{ fontSize: 13, color: "rgba(244,246,248,0.4)", marginTop: 4 }}>
                  {stat.label}
                </div>
              </div>
            </AnimateIn>
          ))}
        </div>
      </section>

      {/* ═══════════════════ TRUST BAR ═══════════════════ */}
      <section
        style={{
          padding: "48px 0",
          background: "var(--bg-alt)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div
          style={{
            maxWidth: 1200,
            margin: "0 auto",
            padding: "0 24px",
            textAlign: "center",
          }}
        >
          <p
            style={{
              fontSize: 12,
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.1em",
              color: "var(--text-muted)",
              marginBottom: 24,
            }}
          >
            Powered by world-class intelligence sources
          </p>
          <div
            style={{
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              gap: 40,
              flexWrap: "wrap",
            }}
          >
            {TRUST_LOGOS.map((name) => (
              <span
                key={name}
                style={{
                  fontSize: 14,
                  fontWeight: 600,
                  color: "var(--text-muted)",
                  opacity: 0.5,
                  transition: "opacity 0.3s",
                }}
              >
                {name}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════════════ CAPABILITIES ═══════════════════ */}
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
                Capabilities
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
                Everything you need to stay ahead
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
                From detection to response — Argus covers the full threat lifecycle
                with AI-first intelligence.
              </p>
            </div>
          </AnimateIn>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: 24,
            }}
            className="cap-grid"
          >
            {CAPABILITIES.map((cap, i) => {
              const Icon = cap.icon;
              return (
                <AnimateIn key={cap.title} delay={i * 0.08}>
                  <div
                    style={{
                      padding: 32,
                      borderRadius: 16,
                      border: "1px solid var(--border)",
                      background: "var(--bg-card)",
                      transition: "all 0.35s",
                      cursor: "default",
                      height: "100%",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = cap.color;
                      e.currentTarget.style.boxShadow = `0 0 40px ${cap.color}15, 0 20px 60px rgba(0,0,0,0.1)`;
                      e.currentTarget.style.transform = "translateY(-4px)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = "var(--border)";
                      e.currentTarget.style.boxShadow = "none";
                      e.currentTarget.style.transform = "translateY(0)";
                    }}
                  >
                    <div
                      style={{
                        width: 48,
                        height: 48,
                        borderRadius: 12,
                        background: `${cap.color}12`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        marginBottom: 20,
                      }}
                    >
                      <Icon size={22} style={{ color: cap.color }} />
                    </div>
                    <h3
                      style={{
                        fontSize: 18,
                        fontWeight: 600,
                        color: "var(--text)",
                        marginBottom: 12,
                      }}
                    >
                      {cap.title}
                    </h3>
                    <p style={{ fontSize: 14, lineHeight: 1.7, color: "var(--text-secondary)" }}>
                      {cap.desc}
                    </p>
                  </div>
                </AnimateIn>
              );
            })}
          </div>
        </div>
      </section>

      {/* ═══════════════════ AGENTIC AI SECTION ═══════════════════ */}
      <section
        style={{
          padding: "120px 0",
          background: "var(--bg-alt)",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Decorative gradient orb */}
        <div
          style={{
            position: "absolute",
            width: 600,
            height: 600,
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(142,51,255,0.08) 0%, transparent 70%)",
            top: -200,
            right: -200,
            pointerEvents: "none",
          }}
        />

        <div
          style={{
            maxWidth: 1200,
            margin: "0 auto",
            padding: "0 24px",
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 80,
            alignItems: "center",
          }}
          className="agent-grid"
        >
          <AnimateIn direction="left">
            <div>
              <p
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  color: "var(--secondary)",
                  marginBottom: 16,
                }}
              >
                Agentic Intelligence
              </p>
              <h2
                style={{
                  fontSize: "clamp(32px, 3.5vw, 44px)",
                  fontWeight: 700,
                  lineHeight: 1.15,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                  marginBottom: 24,
                }}
              >
                AI that doesn&apos;t just detect.
                <br />
                <span style={{ color: "var(--secondary)" }}>It decides and acts.</span>
              </h2>
              <p
                style={{
                  fontSize: 16,
                  lineHeight: 1.7,
                  color: "var(--text-secondary)",
                  marginBottom: 32,
                }}
              >
                Argus deploys autonomous AI agents that continuously ingest threat feeds,
                extract indicators of compromise, correlate across your attack surface,
                and generate prioritized alerts — with full reasoning transparency.
              </p>

              {/* Agent steps */}
              {[
                { step: "01", title: "Ingest", desc: "Continuous ingestion from 30+ global threat feeds" },
                { step: "02", title: "Analyze", desc: "LLM-powered classification, severity scoring, and correlation" },
                { step: "03", title: "Act", desc: "Auto-create IOCs, generate alerts, trigger response workflows" },
              ].map((item, i) => (
                <div
                  key={item.step}
                  style={{
                    display: "flex",
                    gap: 16,
                    marginBottom: 20,
                    padding: "16px 20px",
                    borderRadius: 12,
                    border: "1px solid var(--border)",
                    background: "var(--bg-card)",
                  }}
                >
                  <span
                    style={{
                      fontSize: 13,
                      fontWeight: 700,
                      color: "var(--secondary)",
                      fontVariantNumeric: "tabular-nums",
                    }}
                  >
                    {item.step}
                  </span>
                  <div>
                    <div style={{ fontSize: 15, fontWeight: 600, color: "var(--text)", marginBottom: 4 }}>
                      {item.title}
                    </div>
                    <div style={{ fontSize: 13, color: "var(--text-muted)" }}>{item.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </AnimateIn>

          <AnimateIn direction="right" delay={0.2}>
            {/* Agent visualization */}
            <div
              style={{
                position: "relative",
                borderRadius: 20,
                overflow: "hidden",
                border: "1px solid var(--border)",
                background: "#0A0E14",
                padding: 32,
                minHeight: 480,
              }}
            >
              {/* Decorative grid */}
              <div
                style={{
                  position: "absolute",
                  inset: 0,
                  backgroundImage:
                    "linear-gradient(rgba(142,51,255,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(142,51,255,0.04) 1px, transparent 1px)",
                  backgroundSize: "40px 40px",
                }}
              />

              <div style={{ position: "relative", zIndex: 1 }}>
                {/* Simulated agent console */}
                <div style={{ display: "flex", gap: 6, marginBottom: 24 }}>
                  <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#FF5630" }} />
                  <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#FFAB00" }} />
                  <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#22C55E" }} />
                </div>

                {[
                  { time: "07:42:18", text: "Feed ingestion: 847 new entries from 12 feeds", color: "var(--grey-400)" },
                  { time: "07:42:19", text: "DNS resolution: 623 domains → IPs resolved", color: "var(--grey-400)" },
                  { time: "07:42:21", text: "AI triage initiated — analyzing 847 entries", color: "var(--secondary-light)" },
                  { time: "07:42:24", text: "CRITICAL: 3 ransomware C2 servers detected", color: "var(--error)" },
                  { time: "07:42:24", text: "→ IOCs created: 12 IPv4, 8 domains, 3 SHA256", color: "var(--primary-light)" },
                  { time: "07:42:25", text: "→ Alert generated: Ransomware Infrastructure Active", color: "var(--warning)" },
                  { time: "07:42:25", text: "→ SOAR workflow triggered: block_malicious_ips", color: "var(--info)" },
                  { time: "07:42:26", text: "HIGH: Phishing campaign targeting financial sector", color: "var(--error)" },
                  { time: "07:42:27", text: "→ Matched against org assets: 2 domain overlaps", color: "var(--primary-light)" },
                  { time: "07:42:28", text: "INFOCON updated: GREEN → YELLOW", color: "var(--warning)" },
                  { time: "07:42:30", text: "Triage complete: 23 IOCs, 4 alerts, 2 workflows", color: "var(--success)" },
                ].map((line, i) => (
                  <div
                    key={i}
                    style={{
                      fontFamily: "'Space Grotesk', monospace",
                      fontSize: 12,
                      lineHeight: 2.2,
                      display: "flex",
                      gap: 12,
                      opacity: 0,
                      animation: `fade-up 0.4s ease ${0.8 + i * 0.12}s forwards`,
                    }}
                  >
                    <span style={{ color: "var(--grey-600)", fontVariantNumeric: "tabular-nums", flexShrink: 0 }}>
                      {line.time}
                    </span>
                    <span style={{ color: line.color }}>{line.text}</span>
                  </div>
                ))}
              </div>
            </div>
          </AnimateIn>
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
              Ready to see what you&apos;ve been missing?
            </h2>
            <p
              style={{
                fontSize: 17,
                lineHeight: 1.6,
                color: "var(--text-secondary)",
                marginBottom: 40,
              }}
            >
              Deploy Argus and gain instant visibility into global threats targeting
              your organization. No agents to install, no complex setup.
            </p>
            <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
              <Link
                href="https://app.argusai.xyz"
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
                }}
              >
                Launch Dashboard
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
                }}
              >
                View pricing
              </Link>
            </div>
          </AnimateIn>
        </div>
      </section>

      <style>{`
        @media (max-width: 768px) {
          .cap-grid { grid-template-columns: 1fr !important; }
          .agent-grid { grid-template-columns: 1fr !important; }
          .hero-stats { gap: 24px !important; }
        }
        @media (min-width: 769px) and (max-width: 1024px) {
          .cap-grid { grid-template-columns: repeat(2, 1fr) !important; }
        }
      `}</style>
    </>
  );
}
