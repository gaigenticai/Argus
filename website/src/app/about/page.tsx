"use client";

import { useState } from "react";
import { AnimateIn } from "@/components/animate-in";
import {
  Shield,
  Brain,
  Globe,
  Send,
  Database,
  Wrench,
  Radar,
  Zap,
  Users,
  Heart,
} from "lucide-react";

const VALUES = [
  {
    icon: Database,
    title: "Intelligence-first",
    desc: "Every decision backed by real-time global data. We don't guess — we aggregate, correlate, and verify across 30+ threat feeds before surfacing a single alert.",
    color: "var(--primary)",
  },
  {
    icon: Brain,
    title: "Autonomous by design",
    desc: "AI agents that reduce human toil, not replace human judgment. Argus handles the noise so your team can focus on what actually matters — strategic response.",
    color: "var(--secondary)",
  },
  {
    icon: Globe,
    title: "Open ecosystem",
    desc: "Built on the best open-source security tools — OpenCTI, Wazuh, Nuclei, Suricata, and more. No proprietary lock-in. Your data, your infrastructure, your rules.",
    color: "var(--info)",
  },
];

const STATS = [
  { value: "30+", label: "Threat feed sources", icon: Radar },
  { value: "10", label: "Integrated security tools", icon: Wrench },
  { value: "190+", label: "Countries monitored", icon: Globe },
  { value: "24/7", label: "Real-time processing", icon: Zap },
];

export default function AboutPage() {
  const [formData, setFormData] = useState({ name: "", email: "", message: "" });
  const [status, setStatus] = useState<"idle" | "sending" | "sent" | "error">("idle");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus("sending");
    try {
      const res = await fetch("/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });
      if (!res.ok) throw new Error("Failed");
      setStatus("sent");
      setFormData({ name: "", email: "", message: "" });
      setTimeout(() => setStatus("idle"), 5000);
    } catch {
      setStatus("error");
      setTimeout(() => setStatus("idle"), 5000);
    }
  };

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
                Our story
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
              About{" "}
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
              We&apos;re building the threat intelligence platform we wished existed
              — one that watches everything, understands context, and actually helps
              you act before it&apos;s too late.
            </p>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ MISSION ═══════════════════ */}
      <section style={{ padding: "120px 0", background: "var(--bg)" }}>
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
          className="about-mission-grid"
        >
          <AnimateIn direction="left">
            <div>
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
                Our mission
              </p>
              <h2
                style={{
                  fontSize: "clamp(28px, 3.5vw, 40px)",
                  fontWeight: 700,
                  lineHeight: 1.15,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                  marginBottom: 24,
                }}
              >
                Threat intelligence shouldn&apos;t be a luxury reserved for the Fortune 500.
              </h2>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 20,
                }}
              >
                <p
                  style={{
                    fontSize: 16,
                    lineHeight: 1.7,
                    color: "var(--text-secondary)",
                  }}
                >
                  In a world where cyber threats evolve faster than human teams can respond,
                  we built Argus to be the always-on intelligence layer that never sleeps.
                  It watches the feeds your team doesn&apos;t have time to read, catches the
                  patterns a single analyst would miss, and surfaces the signals that matter
                  before they become incidents.
                </p>
                <p
                  style={{
                    fontSize: 16,
                    lineHeight: 1.7,
                    color: "var(--text-secondary)",
                  }}
                >
                  Our vision is simple: democratize enterprise-grade threat intelligence
                  using AI. Whether you&apos;re a three-person security team at a startup or
                  a SOC running 24/7, Argus gives you the same caliber of intelligence that
                  used to require a dozen analysts and seven-figure contracts.
                </p>
                <p
                  style={{
                    fontSize: 16,
                    lineHeight: 1.7,
                    color: "var(--text-secondary)",
                  }}
                >
                  We don&apos;t believe in black-box security. Every alert comes with full
                  reasoning, every decision is auditable, and every tool in our stack is
                  open-source. Because trust in security starts with transparency.
                </p>
              </div>
            </div>
          </AnimateIn>

          <AnimateIn direction="right" delay={0.2}>
            <div
              style={{
                borderRadius: 20,
                border: "1px solid var(--border)",
                background: "var(--bg-card)",
                padding: 40,
                position: "relative",
                overflow: "hidden",
              }}
            >
              {/* Decorative gradient */}
              <div
                style={{
                  position: "absolute",
                  width: 300,
                  height: 300,
                  borderRadius: "50%",
                  background:
                    "radial-gradient(circle, rgba(0,167,111,0.08) 0%, transparent 70%)",
                  top: -100,
                  right: -100,
                  pointerEvents: "none",
                }}
              />

              <div style={{ position: "relative", zIndex: 1 }}>
                <div
                  style={{
                    width: 56,
                    height: 56,
                    borderRadius: 14,
                    background: "rgba(0,167,111,0.1)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    marginBottom: 24,
                  }}
                >
                  <Heart size={26} style={{ color: "var(--primary)" }} />
                </div>

                <h3
                  style={{
                    fontSize: 22,
                    fontWeight: 700,
                    color: "var(--text)",
                    marginBottom: 16,
                    lineHeight: 1.3,
                  }}
                >
                  &ldquo;Security is a right, not a feature.&rdquo;
                </h3>
                <p
                  style={{
                    fontSize: 15,
                    lineHeight: 1.7,
                    color: "var(--text-secondary)",
                    marginBottom: 24,
                  }}
                >
                  Every organization, regardless of size or budget, deserves the ability to
                  understand what&apos;s coming at them. That&apos;s why we built Argus on
                  open-source foundations, powered by AI that explains its reasoning, and
                  priced so real teams can actually use it.
                </p>
                <div
                  style={{
                    height: 1,
                    background: "var(--border)",
                    marginBottom: 20,
                  }}
                />
                <p
                  style={{
                    fontSize: 13,
                    color: "var(--text-muted)",
                    fontWeight: 500,
                  }}
                >
                  Argus founding team
                </p>
              </div>
            </div>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ VALUES ═══════════════════ */}
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
            <div style={{ textAlign: "center", marginBottom: 72 }}>
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
                What we believe
              </p>
              <h2
                style={{
                  fontSize: "clamp(28px, 4vw, 44px)",
                  fontWeight: 700,
                  lineHeight: 1.15,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                  marginBottom: 16,
                }}
              >
                Principles that shape everything we build
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
                Not just product decisions — these are the beliefs that keep us honest.
              </p>
            </div>
          </AnimateIn>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: 24,
            }}
            className="about-values-grid"
          >
            {VALUES.map((val, i) => {
              const Icon = val.icon;
              return (
                <AnimateIn key={val.title} delay={i * 0.1}>
                  <div
                    style={{
                      padding: 36,
                      borderRadius: 16,
                      border: "1px solid var(--border)",
                      background: "var(--bg-card)",
                      transition: "all 0.35s",
                      cursor: "default",
                      height: "100%",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = val.color;
                      e.currentTarget.style.boxShadow = `0 0 40px ${val.color}15, 0 20px 60px rgba(0,0,0,0.1)`;
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
                        width: 52,
                        height: 52,
                        borderRadius: 14,
                        background: `${val.color}12`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        marginBottom: 24,
                      }}
                    >
                      <Icon size={24} style={{ color: val.color }} />
                    </div>
                    <h3
                      style={{
                        fontSize: 20,
                        fontWeight: 600,
                        color: "var(--text)",
                        marginBottom: 12,
                      }}
                    >
                      {val.title}
                    </h3>
                    <p
                      style={{
                        fontSize: 15,
                        lineHeight: 1.7,
                        color: "var(--text-secondary)",
                      }}
                    >
                      {val.desc}
                    </p>
                  </div>
                </AnimateIn>
              );
            })}
          </div>
        </div>
      </section>

      {/* ═══════════════════ BY THE NUMBERS ═══════════════════ */}
      <section style={{ padding: "100px 0", background: "var(--bg)" }}>
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
                By the numbers
              </p>
              <h2
                style={{
                  fontSize: "clamp(28px, 4vw, 44px)",
                  fontWeight: 700,
                  lineHeight: 1.15,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                }}
              >
                The scope of what Argus watches
              </h2>
            </div>
          </AnimateIn>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, 1fr)",
              gap: 24,
            }}
            className="about-stats-grid"
          >
            {STATS.map((stat, i) => {
              const Icon = stat.icon;
              return (
                <AnimateIn key={stat.label} delay={i * 0.1}>
                  <div
                    style={{
                      textAlign: "center",
                      padding: "40px 24px",
                      borderRadius: 16,
                      border: "1px solid var(--border)",
                      background: "var(--bg-card)",
                      transition: "all 0.35s",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = "var(--primary)";
                      e.currentTarget.style.transform = "translateY(-2px)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = "var(--border)";
                      e.currentTarget.style.transform = "translateY(0)";
                    }}
                  >
                    <div
                      style={{
                        width: 48,
                        height: 48,
                        borderRadius: 12,
                        background: "rgba(0,167,111,0.1)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        margin: "0 auto 20px",
                      }}
                    >
                      <Icon size={22} style={{ color: "var(--primary)" }} />
                    </div>
                    <div
                      style={{
                        fontSize: "clamp(32px, 4vw, 48px)",
                        fontWeight: 700,
                        color: "var(--text)",
                        letterSpacing: "-0.02em",
                        lineHeight: 1,
                        marginBottom: 8,
                      }}
                    >
                      {stat.value}
                    </div>
                    <div
                      style={{
                        fontSize: 14,
                        color: "var(--text-muted)",
                        fontWeight: 500,
                      }}
                    >
                      {stat.label}
                    </div>
                  </div>
                </AnimateIn>
              );
            })}
          </div>
        </div>
      </section>

      {/* ═══════════════════ TEAM ═══════════════════ */}
      <section
        style={{
          padding: "120px 0",
          background: "var(--bg-alt)",
          borderTop: "1px solid var(--border)",
        }}
      >
        <div style={{ maxWidth: 800, margin: "0 auto", padding: "0 24px" }}>
          <AnimateIn>
            <div
              style={{
                textAlign: "center",
                padding: "56px 48px",
                borderRadius: 20,
                border: "1px solid var(--border)",
                background: "var(--bg-card)",
                position: "relative",
                overflow: "hidden",
              }}
            >
              {/* Decorative gradient */}
              <div
                style={{
                  position: "absolute",
                  width: 400,
                  height: 400,
                  borderRadius: "50%",
                  background:
                    "radial-gradient(circle, rgba(142,51,255,0.06) 0%, transparent 70%)",
                  top: -150,
                  left: "50%",
                  transform: "translateX(-50%)",
                  pointerEvents: "none",
                }}
              />

              <div style={{ position: "relative", zIndex: 1 }}>
                <div
                  style={{
                    width: 64,
                    height: 64,
                    borderRadius: 16,
                    background: "rgba(142,51,255,0.1)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    margin: "0 auto 28px",
                  }}
                >
                  <Users size={28} style={{ color: "var(--secondary)" }} />
                </div>
                <h2
                  style={{
                    fontSize: "clamp(24px, 3vw, 32px)",
                    fontWeight: 700,
                    color: "var(--text)",
                    marginBottom: 16,
                    letterSpacing: "-0.02em",
                  }}
                >
                  Get in touch
                </h2>
                <p
                  style={{
                    fontSize: 16,
                    lineHeight: 1.7,
                    color: "var(--text-secondary)",
                    maxWidth: 520,
                    margin: "0 auto 8px",
                  }}
                >
                  A team of security researchers, AI engineers, and product builders
                  obsessed with making threat intelligence accessible. We&apos;ve spent
                  years in SOCs, built detection engines, and trained models on threat
                  data — now we&apos;re putting all of that into Argus.
                </p>
              </div>
            </div>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ CONTACT ═══════════════════ */}
      <section
        id="contact"
        style={{
          padding: "120px 0",
          background: "var(--bg)",
          borderTop: "1px solid var(--border)",
        }}
      >
        <div
          style={{
            maxWidth: 1200,
            margin: "0 auto",
            padding: "0 24px",
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 80,
            alignItems: "start",
          }}
          className="about-contact-grid"
        >
          <AnimateIn direction="left">
            <div>
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
                Get in touch
              </p>
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
                Let&apos;s talk security.
              </h2>
              <p
                style={{
                  fontSize: 16,
                  lineHeight: 1.7,
                  color: "var(--text-secondary)",
                  marginBottom: 40,
                }}
              >
                Whether you&apos;re evaluating Argus for your team, have a partnership idea,
                or just want to geek out about threat intelligence — we&apos;d love to hear
                from you.
              </p>

              <div
                style={{
                  padding: "20px 24px",
                  borderRadius: 12,
                  background: "rgba(0,167,111,0.06)",
                  border: "1px solid rgba(0,167,111,0.12)",
                  fontSize: 14,
                  lineHeight: 1.7,
                  color: "var(--text-secondary)",
                }}
              >
                Fill out the form and our team will get back to you within 24 hours.
                We respond to every message personally.
              </div>
            </div>
          </AnimateIn>

          <AnimateIn direction="right" delay={0.2}>
            <form
              onSubmit={handleSubmit}
              style={{
                padding: 36,
                borderRadius: 20,
                border: "1px solid var(--border)",
                background: "var(--bg-card)",
                display: "flex",
                flexDirection: "column",
                gap: 20,
              }}
            >
              <div>
                <label
                  style={{
                    display: "block",
                    fontSize: 13,
                    fontWeight: 600,
                    color: "var(--text-secondary)",
                    marginBottom: 8,
                  }}
                >
                  Name
                </label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="Your name"
                  style={{
                    width: "100%",
                    padding: "12px 16px",
                    borderRadius: 10,
                    border: "1px solid var(--border)",
                    background: "var(--surface)",
                    color: "var(--text)",
                    fontSize: 14,
                    fontFamily: "var(--font-body)",
                    outline: "none",
                    transition: "border-color 0.2s",
                  }}
                  onFocus={(e) => (e.currentTarget.style.borderColor = "var(--primary)")}
                  onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
                />
              </div>

              <div>
                <label
                  style={{
                    display: "block",
                    fontSize: 13,
                    fontWeight: 600,
                    color: "var(--text-secondary)",
                    marginBottom: 8,
                  }}
                >
                  Email
                </label>
                <input
                  type="email"
                  required
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  placeholder="you@company.com"
                  style={{
                    width: "100%",
                    padding: "12px 16px",
                    borderRadius: 10,
                    border: "1px solid var(--border)",
                    background: "var(--surface)",
                    color: "var(--text)",
                    fontSize: 14,
                    fontFamily: "var(--font-body)",
                    outline: "none",
                    transition: "border-color 0.2s",
                  }}
                  onFocus={(e) => (e.currentTarget.style.borderColor = "var(--primary)")}
                  onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
                />
              </div>

              <div>
                <label
                  style={{
                    display: "block",
                    fontSize: 13,
                    fontWeight: 600,
                    color: "var(--text-secondary)",
                    marginBottom: 8,
                  }}
                >
                  Message
                </label>
                <textarea
                  required
                  rows={5}
                  value={formData.message}
                  onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                  placeholder="Tell us what you're working on..."
                  style={{
                    width: "100%",
                    padding: "12px 16px",
                    borderRadius: 10,
                    border: "1px solid var(--border)",
                    background: "var(--surface)",
                    color: "var(--text)",
                    fontSize: 14,
                    fontFamily: "var(--font-body)",
                    outline: "none",
                    transition: "border-color 0.2s",
                    resize: "vertical",
                    minHeight: 120,
                  }}
                  onFocus={(e) => (e.currentTarget.style.borderColor = "var(--primary)")}
                  onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
                />
              </div>

              <button
                type="submit"
                disabled={status === "sending"}
                style={{
                  height: 48,
                  padding: "0 28px",
                  borderRadius: 12,
                  background: status === "sending" ? "var(--text-muted)" : "var(--primary)",
                  color: "#fff",
                  fontSize: 15,
                  fontWeight: 600,
                  fontFamily: "var(--font-body)",
                  border: "none",
                  cursor: status === "sending" ? "not-allowed" : "pointer",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 8,
                  transition: "all 0.25s",
                  alignSelf: "flex-start",
                  opacity: status === "sending" ? 0.7 : 1,
                }}
                onMouseEnter={(e) => {
                  if (status !== "sending") {
                    e.currentTarget.style.background = "var(--primary-dark)";
                    e.currentTarget.style.transform = "translateY(-1px)";
                  }
                }}
                onMouseLeave={(e) => {
                  if (status !== "sending") {
                    e.currentTarget.style.background = "var(--primary)";
                    e.currentTarget.style.transform = "translateY(0)";
                  }
                }}
              >
                {status === "sending" ? "Sending..." : "Send message"}
                <Send size={15} />
              </button>

              {status === "sent" && (
                <div
                  style={{
                    padding: "12px 16px",
                    borderRadius: 10,
                    background: "rgba(34,197,94,0.1)",
                    border: "1px solid rgba(34,197,94,0.2)",
                    color: "var(--success)",
                    fontSize: 14,
                    fontWeight: 500,
                  }}
                >
                  Message sent! We&apos;ll get back to you soon.
                </div>
              )}

              {status === "error" && (
                <div
                  style={{
                    padding: "12px 16px",
                    borderRadius: 10,
                    background: "rgba(255,86,48,0.1)",
                    border: "1px solid rgba(255,86,48,0.2)",
                    color: "var(--error)",
                    fontSize: 14,
                    fontWeight: 500,
                  }}
                >
                  Something went wrong. Please try again or email us directly.
                </div>
              )}
            </form>
          </AnimateIn>
        </div>
      </section>

      <style>{`
        @media (max-width: 768px) {
          .about-mission-grid { grid-template-columns: 1fr !important; gap: 48px !important; }
          .about-values-grid { grid-template-columns: 1fr !important; }
          .about-stats-grid { grid-template-columns: repeat(2, 1fr) !important; }
          .about-contact-grid { grid-template-columns: 1fr !important; gap: 48px !important; }
        }
        @media (min-width: 769px) and (max-width: 1024px) {
          .about-values-grid { grid-template-columns: 1fr !important; max-width: 560px; margin: 0 auto; }
          .about-stats-grid { grid-template-columns: repeat(2, 1fr) !important; }
        }
        input::placeholder,
        textarea::placeholder {
          color: var(--text-muted);
          opacity: 0.7;
        }
      `}</style>
    </>
  );
}
