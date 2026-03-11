"use client";

import { useState } from "react";
import Link from "next/link";
import { AnimateIn } from "@/components/animate-in";
import { Check, X, Zap, Shield, Building2, Crown } from "lucide-react";

const TIERS = [
  {
    name: "Community",
    price: "Free",
    period: "",
    description: "For security researchers and small teams getting started with threat intelligence.",
    icon: Shield,
    color: "var(--text-secondary)",
    features: [
      { text: "Up to 3 organizations", included: true },
      { text: "5 threat feed sources", included: true },
      { text: "Global threat map", included: true },
      { text: "Basic alerting", included: true },
      { text: "Community support", included: true },
      { text: "Agentic AI triage", included: false },
      { text: "Dark web monitoring", included: false },
      { text: "SOAR automation", included: false },
    ],
    cta: "Get started free",
    ctaHref: "https://argusai.xyz",
    ctaStyle: "ghost" as const,
    popular: false,
  },
  {
    name: "Professional",
    price: "$199",
    period: "/mo",
    description: "Full AI-powered threat intelligence for security teams that need to move fast.",
    icon: Zap,
    color: "var(--primary)",
    features: [
      { text: "Unlimited organizations", included: true },
      { text: "All 30+ threat feeds", included: true },
      { text: "Agentic AI triage", included: true },
      { text: "10 integrated security tools", included: true },
      { text: "Dark web monitoring", included: true },
      { text: "SOAR automation", included: true },
      { text: "Priority support", included: true },
      { text: "PDF reports & exports", included: true },
    ],
    cta: "Start free trial",
    ctaHref: "https://argusai.xyz",
    ctaStyle: "primary" as const,
    popular: true,
  },
  {
    name: "Enterprise",
    price: "Custom",
    period: "",
    description: "Dedicated infrastructure and white-glove support for large security operations.",
    icon: Building2,
    color: "var(--secondary)",
    features: [
      { text: "Everything in Professional", included: true },
      { text: "Self-hosted deployment", included: true },
      { text: "Custom integrations", included: true },
      { text: "Dedicated account manager", included: true },
      { text: "SLA guarantee", included: true },
      { text: "SSO / SAML", included: true },
      { text: "On-premise option", included: true },
      { text: "Custom threat feed ingestion", included: true },
    ],
    cta: "Contact sales",
    ctaHref: "mailto:sales@argusai.xyz",
    ctaStyle: "secondary" as const,
    popular: false,
  },
];

const FAQS = [
  {
    q: "What's included in the free tier?",
    a: "The Community plan gives you access to the global threat map, up to 5 curated threat feed sources, basic alerting for up to 3 organizations, and community support. It's a great way to explore Argus and understand how real-time threat intelligence works before upgrading.",
  },
  {
    q: "How does the AI triage work?",
    a: "Argus deploys autonomous AI agents that continuously ingest data from 30+ threat feeds. These agents extract indicators of compromise, correlate them against your organization's attack surface, assign severity scores, and generate prioritized alerts — all without human intervention. Every decision includes full reasoning transparency so your team can audit the logic.",
  },
  {
    q: "Can I self-host Argus?",
    a: "Yes. Our Enterprise plan includes a fully self-hosted deployment option. You get the complete Argus stack — including OpenCTI, Wazuh, and all integrated tools — running on your own infrastructure. We provide deployment guides, Docker Compose configurations, and dedicated support for on-premise installations.",
  },
  {
    q: "What security tools are included?",
    a: "Argus integrates 10+ world-class open-source security tools into a unified platform: OpenCTI for threat intelligence management, Wazuh for endpoint detection, Nuclei for vulnerability scanning, YARA and Sigma for rule-based detection, SpiderFoot for OSINT, Suricata for network monitoring, Shuffle for SOAR automation, GoPhish for phishing simulation, and Prowler for cloud security posture management.",
  },
  {
    q: "Do you offer discounts for startups?",
    a: "Absolutely. We offer a 50% discount on the Professional plan for startups with fewer than 50 employees and under $5M in funding. Reach out to our sales team with proof of eligibility and we'll get you set up within 24 hours.",
  },
  {
    q: "How do I cancel my subscription?",
    a: "You can cancel your Professional plan at any time from your account settings — no questions asked, no hidden fees. Your access continues until the end of your current billing period. For Enterprise contracts, cancellation terms are outlined in your service agreement.",
  },
];

function FAQItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false);

  return (
    <div
      style={{
        borderBottom: "1px solid var(--border)",
        overflow: "hidden",
      }}
    >
      <button
        onClick={() => setOpen(!open)}
        style={{
          width: "100%",
          padding: "24px 0",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 16,
          background: "none",
          border: "none",
          cursor: "pointer",
          textAlign: "left",
          fontFamily: "inherit",
        }}
      >
        <span
          style={{
            fontSize: 16,
            fontWeight: 600,
            color: "var(--text)",
            lineHeight: 1.4,
          }}
        >
          {q}
        </span>
        <span
          style={{
            fontSize: 24,
            color: "var(--text-muted)",
            flexShrink: 0,
            transition: "transform 0.3s",
            transform: open ? "rotate(45deg)" : "rotate(0deg)",
            lineHeight: 1,
          }}
        >
          +
        </span>
      </button>
      <div
        style={{
          maxHeight: open ? 300 : 0,
          opacity: open ? 1 : 0,
          transition: "max-height 0.4s ease, opacity 0.3s ease",
          overflow: "hidden",
        }}
      >
        <p
          style={{
            fontSize: 15,
            lineHeight: 1.7,
            color: "var(--text-secondary)",
            paddingBottom: 24,
          }}
        >
          {a}
        </p>
      </div>
    </div>
  );
}

export default function PricingPage() {
  return (
    <>
      {/* ═══════════════════ HERO ═══════════════════ */}
      <section
        style={{
          padding: "160px 0 80px",
          background: "var(--bg)",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Decorative gradient orb */}
        <div
          style={{
            position: "absolute",
            width: 800,
            height: 800,
            borderRadius: "50%",
            background:
              "radial-gradient(circle, rgba(0,167,111,0.06) 0%, transparent 70%)",
            top: -400,
            left: "50%",
            transform: "translateX(-50%)",
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
              <Crown size={14} style={{ color: "var(--primary)" }} />
              <span
                style={{
                  fontSize: 13,
                  fontWeight: 500,
                  color: "var(--primary)",
                }}
              >
                Pricing
              </span>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.2}>
            <h1
              style={{
                fontSize: "clamp(36px, 5vw, 56px)",
                fontWeight: 700,
                lineHeight: 1.1,
                letterSpacing: "-0.03em",
                color: "var(--text)",
                marginBottom: 20,
              }}
            >
              Simple, transparent pricing
            </h1>
          </AnimateIn>

          <AnimateIn delay={0.3}>
            <p
              style={{
                fontSize: "clamp(16px, 2vw, 18px)",
                lineHeight: 1.6,
                color: "var(--text-secondary)",
                maxWidth: 560,
                margin: "0 auto",
              }}
            >
              Start free with community-grade threat intelligence. Upgrade when
              you need AI-powered triage, dark web monitoring, and full SOAR
              automation.
            </p>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ PRICING CARDS ═══════════════════ */}
      <section
        style={{
          padding: "0 0 120px",
          background: "var(--bg)",
        }}
      >
        <div
          style={{
            maxWidth: 1200,
            margin: "0 auto",
            padding: "0 24px",
          }}
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap: 24,
              alignItems: "stretch",
            }}
            className="pricing-grid"
          >
            {TIERS.map((tier, i) => {
              const Icon = tier.icon;
              const isPro = tier.popular;

              return (
                <AnimateIn key={tier.name} delay={i * 0.1}>
                  <div
                    style={{
                      position: "relative",
                      padding: 36,
                      borderRadius: 20,
                      border: isPro
                        ? "2px solid var(--primary)"
                        : "1px solid var(--border)",
                      background: "var(--bg-card)",
                      transition: "all 0.35s",
                      cursor: "default",
                      height: "100%",
                      display: "flex",
                      flexDirection: "column",
                      boxShadow: isPro
                        ? "0 0 60px rgba(0,167,111,0.12), 0 0 120px rgba(0,167,111,0.06)"
                        : "none",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.transform = "translateY(-8px)";
                      e.currentTarget.style.boxShadow = isPro
                        ? "0 0 80px rgba(0,167,111,0.18), 0 20px 60px rgba(0,0,0,0.15)"
                        : "0 20px 60px rgba(0,0,0,0.12)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.transform = "translateY(0)";
                      e.currentTarget.style.boxShadow = isPro
                        ? "0 0 60px rgba(0,167,111,0.12), 0 0 120px rgba(0,167,111,0.06)"
                        : "none";
                    }}
                  >
                    {/* Popular badge */}
                    {isPro && (
                      <div
                        style={{
                          position: "absolute",
                          top: -14,
                          left: "50%",
                          transform: "translateX(-50%)",
                          padding: "6px 20px",
                          borderRadius: 100,
                          background: "var(--primary)",
                          color: "#fff",
                          fontSize: 12,
                          fontWeight: 700,
                          letterSpacing: "0.06em",
                          textTransform: "uppercase",
                        }}
                      >
                        Popular
                      </div>
                    )}

                    {/* Icon + Tier name */}
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 12,
                        marginBottom: 20,
                      }}
                    >
                      <div
                        style={{
                          width: 44,
                          height: 44,
                          borderRadius: 12,
                          background: `${tier.color}12`,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                        }}
                      >
                        <Icon size={20} style={{ color: tier.color }} />
                      </div>
                      <span
                        style={{
                          fontSize: 18,
                          fontWeight: 600,
                          color: "var(--text)",
                        }}
                      >
                        {tier.name}
                      </span>
                    </div>

                    {/* Price */}
                    <div
                      style={{
                        marginBottom: 12,
                        display: "flex",
                        alignItems: "baseline",
                        gap: 4,
                      }}
                    >
                      <span
                        style={{
                          fontSize: tier.price === "Custom" ? 36 : 48,
                          fontWeight: 700,
                          color: "var(--text)",
                          letterSpacing: "-0.03em",
                          lineHeight: 1,
                        }}
                      >
                        {tier.price}
                      </span>
                      {tier.period && (
                        <span
                          style={{
                            fontSize: 16,
                            color: "var(--text-muted)",
                            fontWeight: 500,
                          }}
                        >
                          {tier.period}
                        </span>
                      )}
                    </div>

                    {/* Description */}
                    <p
                      style={{
                        fontSize: 14,
                        lineHeight: 1.6,
                        color: "var(--text-secondary)",
                        marginBottom: 28,
                      }}
                    >
                      {tier.description}
                    </p>

                    {/* CTA Button */}
                    <Link
                      href={tier.ctaHref}
                      target={tier.ctaStyle === "secondary" ? undefined : "_blank"}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        height: 48,
                        borderRadius: 12,
                        fontSize: 15,
                        fontWeight: 600,
                        textDecoration: "none",
                        transition: "all 0.25s",
                        marginBottom: 28,
                        ...(tier.ctaStyle === "primary"
                          ? {
                              background: "var(--primary)",
                              color: "#fff",
                              border: "none",
                            }
                          : tier.ctaStyle === "secondary"
                          ? {
                              background: "rgba(142,51,255,0.1)",
                              color: "var(--secondary)",
                              border: "1px solid rgba(142,51,255,0.3)",
                            }
                          : {
                              background: "transparent",
                              color: "var(--text)",
                              border: "1px solid var(--border)",
                            }),
                      }}
                    >
                      {tier.cta}
                    </Link>

                    {/* Divider */}
                    <div
                      style={{
                        height: 1,
                        background: "var(--border)",
                        marginBottom: 24,
                      }}
                    />

                    {/* Feature list */}
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: 14,
                        flex: 1,
                      }}
                    >
                      {tier.features.map((f) => (
                        <div
                          key={f.text}
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 12,
                          }}
                        >
                          {f.included ? (
                            <Check
                              size={16}
                              style={{
                                color: "var(--primary)",
                                flexShrink: 0,
                              }}
                            />
                          ) : (
                            <X
                              size={16}
                              style={{
                                color: "var(--text-muted)",
                                opacity: 0.4,
                                flexShrink: 0,
                              }}
                            />
                          )}
                          <span
                            style={{
                              fontSize: 14,
                              color: f.included
                                ? "var(--text-secondary)"
                                : "var(--text-muted)",
                              opacity: f.included ? 1 : 0.5,
                            }}
                          >
                            {f.text}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </AnimateIn>
              );
            })}
          </div>
        </div>
      </section>

      {/* ═══════════════════ FAQ ═══════════════════ */}
      <section
        style={{
          padding: "120px 0",
          background: "var(--bg-alt)",
          borderTop: "1px solid var(--border)",
        }}
      >
        <div
          style={{
            maxWidth: 720,
            margin: "0 auto",
            padding: "0 24px",
          }}
        >
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
                FAQ
              </p>
              <h2
                style={{
                  fontSize: "clamp(28px, 3.5vw, 40px)",
                  fontWeight: 700,
                  lineHeight: 1.15,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                }}
              >
                Frequently asked questions
              </h2>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.1}>
            <div
              style={{
                borderTop: "1px solid var(--border)",
              }}
            >
              {FAQS.map((faq) => (
                <FAQItem key={faq.q} q={faq.q} a={faq.a} />
              ))}
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
            background:
              "radial-gradient(circle, rgba(142,51,255,0.06) 0%, transparent 70%)",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            pointerEvents: "none",
          }}
        />

        <div
          style={{
            maxWidth: 640,
            margin: "0 auto",
            padding: "0 24px",
            textAlign: "center",
            position: "relative",
          }}
        >
          <AnimateIn>
            <h2
              style={{
                fontSize: "clamp(28px, 3.5vw, 40px)",
                fontWeight: 700,
                lineHeight: 1.15,
                letterSpacing: "-0.02em",
                color: "var(--text)",
                marginBottom: 16,
              }}
            >
              Not sure which plan?{" "}
              <span style={{ color: "var(--secondary)" }}>
                Let&apos;s talk.
              </span>
            </h2>
            <p
              style={{
                fontSize: 17,
                lineHeight: 1.6,
                color: "var(--text-secondary)",
                marginBottom: 40,
              }}
            >
              Our team can walk you through the platform, answer technical
              questions, and help you find the right fit for your security
              operations.
            </p>
            <div
              style={{
                display: "flex",
                gap: 16,
                justifyContent: "center",
                flexWrap: "wrap",
              }}
            >
              <Link
                href="mailto:sales@argusai.xyz"
                style={{
                  height: 52,
                  padding: "0 32px",
                  borderRadius: 12,
                  background: "var(--secondary)",
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
                Talk to sales
              </Link>
              <Link
                href="https://argusai.xyz"
                target="_blank"
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
                Start free
              </Link>
            </div>
          </AnimateIn>
        </div>
      </section>

      <style>{`
        @media (max-width: 768px) {
          .pricing-grid { grid-template-columns: 1fr !important; max-width: 420px; margin: 0 auto; }
        }
        @media (min-width: 769px) and (max-width: 1024px) {
          .pricing-grid { grid-template-columns: 1fr 1fr !important; }
        }
      `}</style>
    </>
  );
}
