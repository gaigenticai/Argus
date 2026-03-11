"use client";

import Link from "next/link";
import { AnimateIn } from "@/components/animate-in";
import {
  Globe,
  Brain,
  Eye,
  Layers,
  Shield,
  FileText,
  ArrowRight,
  Radio,
  Network,
  Flame,
  Bug,
  Fingerprint,
  AlertTriangle,
  Users,
  KeyRound,
  ScanSearch,
  Cloud,
  BookOpen,
  Clock,
  Target,
  Workflow,
  CheckCircle2,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Feature {
  icon: LucideIcon;
  color: string;
  label: string;
  title: string;
  description: string;
  highlights: { icon: LucideIcon; text: string }[];
}

const FEATURES: Feature[] = [
  {
    icon: Globe,
    color: "var(--primary)",
    label: "Situational Awareness",
    title: "Global Threat Map",
    description:
      "Visualize the threat landscape in real time across every continent. Argus continuously tracks 32,000+ indicators spanning ransomware command-and-control infrastructure, botnet activity, phishing campaigns, malware distribution, actively exploited CVEs, IP reputation signals, and dark web chatter. Animated dots mark live detections, connection arcs reveal attacker infrastructure relationships, and country-level heatmaps surface regional risk concentrations — all updated within seconds of discovery.",
    highlights: [
      { icon: Radio, text: "Live indicator feed with sub-minute latency from 30+ global sources" },
      { icon: Network, text: "Infrastructure relationship mapping with connection arc visualization" },
      { icon: Flame, text: "Regional heatmaps that surface emerging threat clusters by geography" },
      { icon: AlertTriangle, text: "INFOCON-level risk assessment updated continuously" },
    ],
  },
  {
    icon: Brain,
    color: "var(--secondary)",
    label: "Autonomous Intelligence",
    title: "Agentic AI Engine",
    description:
      "Argus deploys purpose-built AI agents that operate autonomously across the entire threat intelligence lifecycle. Raw data flows in from dozens of feeds and emerges as prioritized, actionable intelligence — without human intervention. Each agent specializes in a stage of the pipeline: ingestion, classification, IOC extraction, severity scoring, alert generation, and SOAR workflow orchestration. LLM-powered reasoning provides full transparency into every decision, so your team understands not just what was flagged, but why.",
    highlights: [
      { icon: Workflow, text: "End-to-end autonomous pipeline from raw feed to triggered response" },
      { icon: Target, text: "LLM-powered severity scoring with transparent reasoning chains" },
      { icon: Fingerprint, text: "Automatic IOC extraction — IPs, domains, hashes, CVEs, emails" },
      { icon: AlertTriangle, text: "INFOCON level assessment with continuous global risk calibration" },
    ],
  },
  {
    icon: Eye,
    color: "var(--warning)",
    label: "Underground Intelligence",
    title: "Dark Web Monitoring",
    description:
      "Purpose-built crawlers continuously scan underground forums, paste sites, hidden marketplaces, and encrypted channels where threat actors operate. Argus identifies mentions of your organization, brand, executives, domains, and proprietary assets before they surface in a breach notification. Actor profiling tracks the tactics, reputation, and history of individuals trading in stolen data, exploits, or access credentials — giving your team the context to assess real risk, not just noise.",
    highlights: [
      { icon: ScanSearch, text: "Keyword and entity alerts across forums, paste sites, and markets" },
      { icon: Users, text: "Actor profiling with history, reputation scoring, and TTP mapping" },
      { icon: KeyRound, text: "Credential leak detection matched against your organization's domains" },
      { icon: Bug, text: "Exploit and zero-day chatter tracking with severity classification" },
    ],
  },
  {
    icon: Layers,
    color: "var(--info)",
    label: "Unified Platform",
    title: "Integrated Security Stack",
    description:
      "Ten world-class open-source security tools unified under a single control plane. OpenCTI for structured threat intelligence. Wazuh for endpoint detection and log analysis. Nuclei for template-based vulnerability scanning. YARA and Sigma for malware and detection rule matching. SpiderFoot for automated OSINT reconnaissance. Suricata for network intrusion detection. Shuffle SOAR for automated response playbooks. GoPhish for phishing simulation and awareness training. Prowler for cloud security posture management. Each tool is pre-configured, automatically synchronized, and managed through one interface.",
    highlights: [
      { icon: CheckCircle2, text: "Pre-configured with production-ready defaults — deploy in minutes" },
      { icon: Workflow, text: "Automated data synchronization across all tools in real time" },
      { icon: Layers, text: "Single control plane for configuration, monitoring, and management" },
      { icon: Shield, text: "Consistent alerting and correlation across the entire stack" },
    ],
  },
  {
    icon: Shield,
    color: "var(--error)",
    label: "Proactive Defense",
    title: "Vulnerability Management",
    description:
      "Continuous, automated scanning that covers your entire attack surface — from web applications to cloud infrastructure to endpoint configurations. Nuclei runs thousands of community and custom templates to detect known vulnerabilities, misconfigurations, and exposed services. Prowler audits your AWS, Azure, and GCP environments against CIS benchmarks and compliance frameworks. YARA rules match known malware signatures across your file systems. Sigma detection rules monitor log streams for suspicious patterns that signature-based tools miss.",
    highlights: [
      { icon: ScanSearch, text: "Template-based scanning with 8,000+ Nuclei detection templates" },
      { icon: Cloud, text: "Multi-cloud security posture auditing for AWS, Azure, and GCP" },
      { icon: Bug, text: "YARA rule matching for malware identification across file systems" },
      { icon: BookOpen, text: "Sigma detection rules for behavioral analysis in log streams" },
    ],
  },
  {
    icon: FileText,
    color: "var(--success)",
    label: "Actionable Reporting",
    title: "Intelligence Reports",
    description:
      "Generate comprehensive PDF intelligence reports that transform raw threat data into executive-ready briefings. Each report includes an executive summary with risk posture assessment, detailed threat timelines showing attack progression, complete IOC lists for operational teams, and full MITRE ATT&CK mapping to contextualize adversary behavior. Reports can be auto-generated on schedule or assembled manually for specific investigations. Every output is designed to bridge the gap between technical findings and strategic decision-making.",
    highlights: [
      { icon: FileText, text: "Executive summaries with risk posture and trend analysis" },
      { icon: Clock, text: "Threat timelines showing attack progression and key events" },
      { icon: Target, text: "MITRE ATT&CK mapping for adversary technique contextualization" },
      { icon: Workflow, text: "Scheduled auto-generation or on-demand manual assembly" },
    ],
  },
];

export default function FeaturesPage() {
  return (
    <>
      {/* ═══════════════════ HERO BANNER ═══════════════════ */}
      <section
        style={{
          position: "relative",
          padding: "180px 24px 100px",
          background: "linear-gradient(180deg, #0A0E14 0%, #0F1419 50%, #0A0E14 100%)",
          overflow: "hidden",
          textAlign: "center",
        }}
      >
        {/* Decorative grid background */}
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

        {/* Radial glow */}
        <div
          style={{
            position: "absolute",
            width: 800,
            height: 800,
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(0,167,111,0.08) 0%, transparent 70%)",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            pointerEvents: "none",
          }}
        />

        <div style={{ position: "relative", zIndex: 1, maxWidth: 800, margin: "0 auto" }}>
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
              <span style={{ fontSize: 13, fontWeight: 500, color: "var(--primary-light)" }}>
                Platform Capabilities
              </span>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.2}>
            <h1
              style={{
                fontSize: "clamp(36px, 5.5vw, 64px)",
                fontWeight: 700,
                lineHeight: 1.1,
                letterSpacing: "-0.03em",
                color: "#F4F6F8",
                marginBottom: 24,
              }}
            >
              Built for the threats
              <br />
              <span className="gradient-text">of tomorrow</span>
            </h1>
          </AnimateIn>

          <AnimateIn delay={0.35}>
            <p
              style={{
                fontSize: "clamp(16px, 2vw, 19px)",
                lineHeight: 1.7,
                color: "rgba(244,246,248,0.55)",
                maxWidth: 620,
                margin: "0 auto",
              }}
            >
              From global threat visualization to autonomous AI triage, dark web monitoring
              to automated vulnerability scanning — Argus delivers comprehensive protection
              across every layer of your security posture.
            </p>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ FEATURE DETAIL SECTIONS ═══════════════════ */}
      {FEATURES.map((feature, index) => {
        const Icon = feature.icon;
        const isReversed = index % 2 === 1;

        return (
          <section
            key={feature.title}
            style={{
              padding: "120px 0",
              background: index % 2 === 0 ? "var(--bg)" : "var(--bg-alt)",
              position: "relative",
              overflow: "hidden",
            }}
          >
            {/* Subtle decorative orb */}
            <div
              style={{
                position: "absolute",
                width: 500,
                height: 500,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${feature.color}08 0%, transparent 70%)`,
                top: -100,
                ...(isReversed ? { left: -150 } : { right: -150 }),
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
              className="feature-detail-grid"
              data-reversed={isReversed ? "true" : "false"}
            >
              {/* Text content */}
              <AnimateIn
                direction={isReversed ? "right" : "left"}
                style={{ order: isReversed ? 2 : 1 }}
              >
                <div>
                  <div
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 8,
                      marginBottom: 16,
                    }}
                  >
                    <div
                      style={{
                        width: 32,
                        height: 32,
                        borderRadius: 8,
                        background: `${feature.color}14`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <Icon size={16} style={{ color: feature.color }} />
                    </div>
                    <span
                      style={{
                        fontSize: 13,
                        fontWeight: 600,
                        textTransform: "uppercase",
                        letterSpacing: "0.08em",
                        color: feature.color,
                      }}
                    >
                      {feature.label}
                    </span>
                  </div>

                  <h2
                    style={{
                      fontSize: "clamp(28px, 3.5vw, 40px)",
                      fontWeight: 700,
                      lineHeight: 1.15,
                      letterSpacing: "-0.02em",
                      color: "var(--text)",
                      marginBottom: 20,
                    }}
                  >
                    {feature.title}
                  </h2>

                  <p
                    style={{
                      fontSize: 15,
                      lineHeight: 1.75,
                      color: "var(--text-secondary)",
                      marginBottom: 32,
                    }}
                  >
                    {feature.description}
                  </p>

                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    {feature.highlights.map((hl) => {
                      const HlIcon = hl.icon;
                      return (
                        <div
                          key={hl.text}
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            gap: 12,
                            padding: "12px 16px",
                            borderRadius: 10,
                            border: "1px solid var(--border)",
                            background: "var(--bg-card)",
                            transition: "all 0.3s ease",
                            cursor: "default",
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.borderColor = `${feature.color}40`;
                            e.currentTarget.style.background = `${feature.color}06`;
                            e.currentTarget.style.transform = "translateX(4px)";
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.borderColor = "var(--border)";
                            e.currentTarget.style.background = "var(--bg-card)";
                            e.currentTarget.style.transform = "translateX(0)";
                          }}
                        >
                          <HlIcon
                            size={16}
                            style={{
                              color: feature.color,
                              flexShrink: 0,
                              marginTop: 2,
                            }}
                          />
                          <span
                            style={{
                              fontSize: 14,
                              lineHeight: 1.5,
                              color: "var(--text-secondary)",
                            }}
                          >
                            {hl.text}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </AnimateIn>

              {/* Visual card */}
              <AnimateIn
                direction={isReversed ? "left" : "right"}
                delay={0.15}
                style={{ order: isReversed ? 1 : 2 }}
              >
                <div
                  style={{
                    position: "relative",
                    borderRadius: 20,
                    overflow: "hidden",
                    border: "1px solid var(--border)",
                    background: "#0A0E14",
                    padding: 32,
                    minHeight: 420,
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "center",
                    transition: "all 0.4s ease",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = `${feature.color}30`;
                    e.currentTarget.style.boxShadow = `0 0 60px ${feature.color}10, 0 24px 80px rgba(0,0,0,0.2)`;
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = "var(--border)";
                    e.currentTarget.style.boxShadow = "none";
                  }}
                >
                  {/* Grid pattern */}
                  <div
                    style={{
                      position: "absolute",
                      inset: 0,
                      backgroundImage: `linear-gradient(${feature.color}06 1px, transparent 1px), linear-gradient(90deg, ${feature.color}06 1px, transparent 1px)`,
                      backgroundSize: "40px 40px",
                      pointerEvents: "none",
                    }}
                  />

                  {/* Gradient overlay */}
                  <div
                    style={{
                      position: "absolute",
                      inset: 0,
                      background: `radial-gradient(ellipse at center, ${feature.color}08 0%, transparent 70%)`,
                      pointerEvents: "none",
                    }}
                  />

                  <div style={{ position: "relative", zIndex: 1 }}>
                    {/* Central icon */}
                    <div
                      style={{
                        width: 72,
                        height: 72,
                        borderRadius: 18,
                        background: `${feature.color}12`,
                        border: `1px solid ${feature.color}20`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        margin: "0 auto 28px",
                        animation: "float-slow 6s ease-in-out infinite",
                      }}
                    >
                      <Icon size={32} style={{ color: feature.color }} />
                    </div>

                    {/* Feature-specific visual content */}
                    <FeatureVisual feature={feature} index={index} />
                  </div>
                </div>
              </AnimateIn>
            </div>
          </section>
        );
      })}

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
            width: 900,
            height: 900,
            borderRadius: "50%",
            background:
              "radial-gradient(circle, rgba(0,167,111,0.06) 0%, rgba(142,51,255,0.03) 40%, transparent 70%)",
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
              Start protecting your organization
            </h2>
            <p
              style={{
                fontSize: 17,
                lineHeight: 1.6,
                color: "var(--text-secondary)",
                marginBottom: 40,
                maxWidth: 560,
                margin: "0 auto 40px",
              }}
            >
              Deploy the full Argus platform and gain unified visibility across
              global threats, vulnerabilities, and your entire attack surface — in minutes.
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
                  transition: "all 0.25s",
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
          .feature-detail-grid {
            grid-template-columns: 1fr !important;
            gap: 40px !important;
          }
          .feature-detail-grid > * {
            order: unset !important;
          }
        }
      `}</style>
    </>
  );
}

/* ─── Feature-specific visual content for each dark card ─── */
function FeatureVisual({ feature, index }: { feature: Feature; index: number }) {
  const visuals: Record<number, { lines: { label: string; value: string; color: string }[] }> = {
    0: {
      lines: [
        { label: "Active indicators", value: "32,847", color: "var(--primary-light)" },
        { label: "Ransomware C2s", value: "1,204", color: "var(--error)" },
        { label: "Botnet nodes", value: "4,519", color: "var(--warning)" },
        { label: "Phishing domains", value: "8,732", color: "var(--secondary-light)" },
        { label: "Malware samples", value: "6,891", color: "var(--info)" },
        { label: "Exploit CVEs", value: "2,148", color: "var(--error)" },
        { label: "IP reputation flags", value: "9,353", color: "var(--grey-400)" },
      ],
    },
    1: {
      lines: [
        { label: "Agent status", value: "ALL OPERATIONAL", color: "var(--success)" },
        { label: "Feeds processed", value: "847 entries / 12 feeds", color: "var(--grey-400)" },
        { label: "Classification", value: "Ransomware infrastructure", color: "var(--error)" },
        { label: "IOCs extracted", value: "12 IPv4, 8 domains, 3 SHA256", color: "var(--primary-light)" },
        { label: "Severity", value: "CRITICAL (9.2 / 10)", color: "var(--error)" },
        { label: "SOAR triggered", value: "block_malicious_ips", color: "var(--info)" },
        { label: "Reasoning", value: "Known LockBit infrastructure pattern", color: "var(--secondary-light)" },
      ],
    },
    2: {
      lines: [
        { label: "Forums monitored", value: "47 active sources", color: "var(--grey-400)" },
        { label: "New mention", value: "Organization domain detected", color: "var(--warning)" },
        { label: "Actor identified", value: "threat_actor_x91 (Rep: 4.2/5)", color: "var(--error)" },
        { label: "Data type", value: "Credential dump — 12K records", color: "var(--error)" },
        { label: "Domain match", value: "2 corporate domains found", color: "var(--warning)" },
        { label: "Paste sites", value: "3 new pastes flagged", color: "var(--secondary-light)" },
        { label: "Alert generated", value: "HIGH — Credential Exposure", color: "var(--error)" },
      ],
    },
    3: {
      lines: [
        { label: "OpenCTI", value: "SYNCED", color: "var(--success)" },
        { label: "Wazuh", value: "SYNCED — 14 active agents", color: "var(--success)" },
        { label: "Nuclei", value: "READY — 8,247 templates", color: "var(--success)" },
        { label: "YARA", value: "SYNCED — 1,892 rules", color: "var(--success)" },
        { label: "Suricata", value: "ACTIVE — 0 alerts / 1h", color: "var(--primary-light)" },
        { label: "Shuffle SOAR", value: "12 workflows configured", color: "var(--info)" },
        { label: "Prowler", value: "AWS + GCP — Last scan: 4m ago", color: "var(--primary-light)" },
      ],
    },
    4: {
      lines: [
        { label: "Scan status", value: "RUNNING", color: "var(--primary-light)" },
        { label: "Nuclei templates", value: "8,247 loaded / 23 critical hits", color: "var(--error)" },
        { label: "Prowler (AWS)", value: "342 checks — 7 FAIL", color: "var(--warning)" },
        { label: "Prowler (GCP)", value: "218 checks — 2 FAIL", color: "var(--warning)" },
        { label: "YARA matches", value: "3 suspicious binaries flagged", color: "var(--error)" },
        { label: "Sigma rules", value: "4 behavioral detections triggered", color: "var(--secondary-light)" },
        { label: "Next scan", value: "Scheduled in 47 minutes", color: "var(--grey-400)" },
      ],
    },
    5: {
      lines: [
        { label: "Report type", value: "Weekly Threat Intelligence Brief", color: "var(--grey-400)" },
        { label: "Executive summary", value: "Risk elevated — 3 active campaigns", color: "var(--warning)" },
        { label: "IOCs included", value: "147 indicators across 6 categories", color: "var(--primary-light)" },
        { label: "MITRE mapping", value: "T1566, T1059, T1071, T1486", color: "var(--secondary-light)" },
        { label: "Timeline events", value: "23 key events over 7 days", color: "var(--info)" },
        { label: "Format", value: "PDF — 12 pages generated", color: "var(--grey-400)" },
        { label: "Distribution", value: "Sent to 8 stakeholders", color: "var(--success)" },
      ],
    },
  };

  const data = visuals[index];
  if (!data) return null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
      {data.lines.map((line, i) => (
        <div
          key={i}
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "10px 16px",
            borderBottom: i < data.lines.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none",
            opacity: 0,
            animation: `fade-up 0.4s ease ${0.3 + i * 0.1}s forwards`,
          }}
        >
          <span
            style={{
              fontSize: 13,
              color: "var(--grey-400)",
              fontFamily: "'Space Grotesk', monospace",
            }}
          >
            {line.label}
          </span>
          <span
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: line.color,
              fontFamily: "'Space Grotesk', monospace",
              textAlign: "right",
            }}
          >
            {line.value}
          </span>
        </div>
      ))}
    </div>
  );
}
