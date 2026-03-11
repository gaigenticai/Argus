"use client";

import { AnimateIn } from "@/components/animate-in";
import { Shield } from "lucide-react";

const SECTIONS = [
  {
    id: "information-we-collect",
    title: "1. Information We Collect",
    content: [
      {
        subtitle: "Account Information",
        text: "When you create an Argus account, we collect information such as your name, email address, organization name, job title, and billing details. If you sign up using a third-party authentication provider (e.g., Google, GitHub, or SSO/SAML), we receive basic profile information from that provider.",
      },
      {
        subtitle: "Usage Data",
        text: "We automatically collect information about how you interact with the Argus platform, including pages visited, features used, search queries, dashboard configurations, alert preferences, and timestamps of activity. This data helps us understand how teams use Argus so we can improve the product.",
      },
      {
        subtitle: "Threat Intelligence Data",
        text: "Argus processes threat intelligence data that you configure the platform to ingest, including indicators of compromise (IOCs), threat feed subscriptions, organization-specific watchlists, dark web monitoring parameters, and vulnerability scan results. This data is processed to deliver the core threat intelligence service.",
      },
      {
        subtitle: "Log Data",
        text: "Our servers automatically record information including your IP address, browser type and version, operating system, referring URLs, device identifiers, access times, and API call metadata. We use this data for security monitoring, debugging, and platform reliability.",
      },
    ],
  },
  {
    id: "how-we-use",
    title: "2. How We Use Your Information",
    content: [
      {
        subtitle: "Platform Operation",
        text: "We use your information to provide, maintain, and secure the Argus platform. This includes authenticating your identity, managing your account, processing billing transactions, delivering threat alerts, and providing customer support.",
      },
      {
        subtitle: "Threat Analysis and Intelligence Delivery",
        text: "Your configured threat parameters and watchlists are used to correlate data across our 30+ integrated threat feed sources, run AI-powered triage and analysis, generate threat reports, and deliver actionable intelligence to your dashboard and alert channels.",
      },
      {
        subtitle: "Service Improvement",
        text: "We use aggregated and anonymized usage data to improve Argus, including enhancing our AI models, refining threat correlation algorithms, developing new features, and optimizing platform performance. We do not use your organization-specific threat data to train general-purpose AI models without your explicit consent.",
      },
      {
        subtitle: "Communication",
        text: "We may use your email address to send transactional messages (account verification, billing receipts, security alerts), product updates, and service announcements. You can opt out of non-essential communications at any time through your account settings or by contacting us.",
      },
    ],
  },
  {
    id: "data-sharing",
    title: "3. Data Sharing and Disclosure",
    content: [
      {
        subtitle: "We Do Not Sell Your Data",
        text: "Gaigentic AI does not sell, rent, or trade your personal information or threat intelligence data to third parties. Your data is not used for advertising purposes.",
      },
      {
        subtitle: "Service Providers",
        text: "We share information with a limited number of trusted service providers who assist us in operating the platform, including cloud infrastructure providers, payment processors, email delivery services, and analytics tools. These providers are contractually bound to use your data only for the purposes we specify and to maintain appropriate security measures.",
      },
      {
        subtitle: "Legal Requirements",
        text: "We may disclose your information if required to do so by law, regulation, legal process, or enforceable governmental request. We may also disclose information when we believe in good faith that disclosure is necessary to protect our rights, your safety, or the safety of others, to investigate fraud, or to respond to a government request. Where legally permitted, we will notify you of such requests.",
      },
      {
        subtitle: "Business Transfers",
        text: "In the event of a merger, acquisition, reorganization, or sale of assets, your information may be transferred as part of that transaction. We will notify you via email or prominent notice on the platform before your information becomes subject to a different privacy policy.",
      },
    ],
  },
  {
    id: "data-security",
    title: "4. Data Security",
    content: [
      {
        subtitle: "Encryption",
        text: "All data transmitted between your browser and Argus is encrypted using TLS 1.3. Data at rest is encrypted using AES-256 encryption. API keys and sensitive credentials stored within the platform are encrypted with additional application-level encryption.",
      },
      {
        subtitle: "Access Controls",
        text: "We implement strict role-based access controls (RBAC) within our organization. Access to customer data is limited to authorized personnel who require it to perform their job functions. All access is logged and auditable.",
      },
      {
        subtitle: "Infrastructure Security",
        text: "Our infrastructure is hosted in SOC 2 compliant data centers with physical security controls, redundant power and networking, and continuous monitoring. We employ firewalls, intrusion detection systems, and DDoS protection.",
      },
      {
        subtitle: "Security Audits",
        text: "We conduct regular security assessments including automated vulnerability scanning, penetration testing, and code reviews. We also maintain an internal security incident response plan and will notify affected users promptly in the event of a data breach, in accordance with applicable law.",
      },
    ],
  },
  {
    id: "data-retention",
    title: "5. Data Retention",
    content: [
      {
        subtitle: "Account Data",
        text: "We retain your account information for as long as your account is active. If you request account deletion, we will delete or anonymize your personal information within 30 days, except where we are required to retain it for legal, regulatory, or legitimate business purposes (such as fraud prevention or financial record-keeping).",
      },
      {
        subtitle: "Threat Intelligence Data",
        text: "Threat intelligence data processed by Argus on your behalf is retained according to the retention settings you configure in your account. By default, historical threat data is retained for 12 months to enable trend analysis and historical correlation. You may adjust this period or request early deletion at any time.",
      },
      {
        subtitle: "Log Data",
        text: "Server logs and usage analytics are retained for up to 90 days for operational purposes. Aggregated, anonymized analytics data may be retained indefinitely for product improvement.",
      },
    ],
  },
  {
    id: "your-rights",
    title: "6. Your Rights",
    content: [
      {
        subtitle: "Access",
        text: "You have the right to request a copy of the personal information we hold about you. You can access most of this information directly through your Argus account settings. For a comprehensive data export, contact us at cto@gaigentic.ai.",
      },
      {
        subtitle: "Correction",
        text: "You have the right to request correction of inaccurate or incomplete personal information. You can update most account details directly in your account settings, or contact us for assistance.",
      },
      {
        subtitle: "Deletion",
        text: "You have the right to request deletion of your personal information. Upon receiving a verified deletion request, we will delete your data within 30 days, subject to legal retention obligations. Note that deleting your account will permanently remove your threat intelligence configurations, alerts, and historical data.",
      },
      {
        subtitle: "Data Export",
        text: "You have the right to receive your data in a structured, commonly used, machine-readable format. Argus supports data export in JSON and CSV formats through the platform interface and API. You may export your threat intelligence data, alert history, and account information at any time.",
      },
      {
        subtitle: "Objection and Restriction",
        text: "You have the right to object to certain processing of your personal information, and to request that we restrict processing in certain circumstances. To exercise these rights, contact us at cto@gaigentic.ai.",
      },
    ],
  },
  {
    id: "cookies",
    title: "7. Cookies and Tracking Technologies",
    content: [
      {
        subtitle: "Essential Cookies",
        text: "We use strictly necessary cookies to authenticate your session, maintain your security preferences, and enable core platform functionality. These cookies cannot be disabled as they are required for Argus to function properly.",
      },
      {
        subtitle: "Analytics Cookies",
        text: "With your consent, we use analytics cookies to understand how users interact with Argus, measure feature adoption, and identify areas for improvement. We use privacy-respecting analytics tools and do not share analytics data with advertising networks. You can manage your cookie preferences at any time through the cookie settings accessible from the platform footer.",
      },
      {
        subtitle: "No Third-Party Advertising",
        text: "Argus does not use advertising cookies or tracking pixels. We do not participate in ad networks or allow third-party advertisers to track our users.",
      },
    ],
  },
  {
    id: "changes",
    title: "8. Changes to This Policy",
    content: [
      {
        subtitle: "",
        text: 'We may update this Privacy Policy from time to time to reflect changes in our practices, technology, legal requirements, or other factors. When we make material changes, we will notify you by email (sent to the address associated with your account) and by posting a prominent notice on the Argus platform at least 30 days before the changes take effect. We encourage you to review this policy periodically. Your continued use of Argus after the effective date of a revised policy constitutes your acceptance of the changes. The "Last updated" date at the top of this page indicates when this policy was most recently revised.',
      },
    ],
  },
  {
    id: "contact",
    title: "9. Contact Us",
    content: [
      {
        subtitle: "",
        text: "If you have any questions, concerns, or requests regarding this Privacy Policy or our data practices, please contact us:",
      },
    ],
  },
];

export default function PrivacyPolicyPage() {
  return (
    <>
      {/* ---- HERO ---- */}
      <section
        style={{
          position: "relative",
          minHeight: "50vh",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          background: "var(--hero-bg)",
          overflow: "hidden",
          padding: "140px 24px 80px",
        }}
      >
        <div
          style={{
            position: "absolute",
            width: 600,
            height: 600,
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
            position: "absolute",
            inset: 0,
            backgroundImage:
              "linear-gradient(rgba(0,167,111,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,167,111,0.03) 1px, transparent 1px)",
            backgroundSize: "60px 60px",
            pointerEvents: "none",
          }}
        />
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
                Legal
              </span>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.2}>
            <h1
              style={{
                fontSize: "clamp(36px, 5vw, 56px)",
                fontWeight: 700,
                lineHeight: 1.08,
                letterSpacing: "-0.03em",
                color: "#F4F6F8",
                marginBottom: 24,
              }}
            >
              Privacy Policy
            </h1>
          </AnimateIn>

          <AnimateIn delay={0.35}>
            <p
              style={{
                fontSize: "clamp(15px, 1.8vw, 18px)",
                lineHeight: 1.6,
                color: "rgba(244,246,248,0.6)",
                maxWidth: 600,
                margin: "0 auto",
              }}
            >
              How Gaigentic AI collects, uses, and protects your data when you
              use the Argus threat intelligence platform.
            </p>
          </AnimateIn>
        </div>
      </section>

      {/* ---- POLICY CONTENT ---- */}
      <section
        style={{
          padding: "80px 0 120px",
          background: "var(--bg)",
        }}
      >
        <div
          style={{
            maxWidth: 800,
            margin: "0 auto",
            padding: "0 24px",
          }}
        >
          <AnimateIn delay={0.1}>
            <div
              style={{
                padding: "20px 24px",
                borderRadius: 12,
                border: "1px solid var(--border)",
                background: "var(--bg-alt)",
                marginBottom: 48,
                display: "flex",
                alignItems: "center",
                gap: 12,
              }}
            >
              <div
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  background: "var(--primary)",
                  flexShrink: 0,
                }}
              />
              <p
                style={{
                  fontSize: 14,
                  color: "var(--text-secondary)",
                  lineHeight: 1.6,
                  margin: 0,
                }}
              >
                <strong style={{ color: "var(--text)", fontWeight: 600 }}>
                  Last updated: March 11, 2026.
                </strong>{" "}
                This Privacy Policy applies to the Argus platform operated by
                Gaigentic AI, accessible at{" "}
                <a
                  href="https://argusai.xyz"
                  style={{ color: "var(--primary)", textDecoration: "none" }}
                >
                  argusai.xyz
                </a>
                .
              </p>
            </div>
          </AnimateIn>

          <AnimateIn delay={0.15}>
            <p
              style={{
                fontSize: 16,
                lineHeight: 1.8,
                color: "var(--text-secondary)",
                marginBottom: 48,
              }}
            >
              Gaigentic AI (&quot;we,&quot; &quot;us,&quot; or &quot;our&quot;)
              is committed to protecting the privacy and security of your
              personal information. This Privacy Policy describes how we collect,
              use, disclose, and safeguard your information when you use the
              Argus threat intelligence platform, our website at argusai.xyz, and
              any related services (collectively, the &quot;Service&quot;). By
              using Argus, you agree to the collection and use of information in
              accordance with this policy.
            </p>
          </AnimateIn>

          {/* ---- TABLE OF CONTENTS ---- */}
          <AnimateIn delay={0.2}>
            <nav
              style={{
                padding: "28px 32px",
                borderRadius: 16,
                border: "1px solid var(--border)",
                background: "var(--bg-alt)",
                marginBottom: 56,
              }}
            >
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
                Contents
              </p>
              <ol
                style={{
                  margin: 0,
                  padding: "0 0 0 20px",
                  display: "flex",
                  flexDirection: "column",
                  gap: 8,
                }}
              >
                {SECTIONS.map((section) => (
                  <li key={section.id} style={{ fontSize: 14 }}>
                    <a
                      href={`#${section.id}`}
                      style={{
                        color: "var(--text-secondary)",
                        textDecoration: "none",
                        transition: "color 0.2s",
                        lineHeight: 1.6,
                      }}
                      onMouseEnter={(e) =>
                        (e.currentTarget.style.color = "var(--primary)")
                      }
                      onMouseLeave={(e) =>
                        (e.currentTarget.style.color = "var(--text-secondary)")
                      }
                    >
                      {section.title.replace(/^\d+\.\s*/, "")}
                    </a>
                  </li>
                ))}
              </ol>
            </nav>
          </AnimateIn>

          {/* ---- SECTIONS ---- */}
          {SECTIONS.map((section, sIdx) => (
            <AnimateIn key={section.id} delay={0.1 + sIdx * 0.03}>
              <div
                id={section.id}
                style={{
                  marginBottom: 48,
                  scrollMarginTop: 100,
                }}
              >
                <h2
                  style={{
                    fontSize: "clamp(22px, 3vw, 28px)",
                    fontWeight: 700,
                    color: "var(--text)",
                    marginBottom: 24,
                    letterSpacing: "-0.02em",
                    lineHeight: 1.3,
                    paddingBottom: 16,
                    borderBottom: "1px solid var(--border)",
                  }}
                >
                  {section.title}
                </h2>

                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 20,
                  }}
                >
                  {section.content.map((item, cIdx) => (
                    <div key={cIdx}>
                      {item.subtitle && (
                        <h3
                          style={{
                            fontSize: 17,
                            fontWeight: 600,
                            color: "var(--text)",
                            marginBottom: 8,
                            lineHeight: 1.4,
                          }}
                        >
                          {item.subtitle}
                        </h3>
                      )}
                      <p
                        style={{
                          fontSize: 15,
                          lineHeight: 1.8,
                          color: "var(--text-secondary)",
                          margin: 0,
                        }}
                      >
                        {item.text}
                      </p>
                    </div>
                  ))}

                  {/* Contact details for the Contact section */}
                  {section.id === "contact" && (
                    <div
                      style={{
                        padding: "24px 28px",
                        borderRadius: 14,
                        border: "1px solid var(--border)",
                        background: "var(--bg-alt)",
                        display: "flex",
                        flexDirection: "column",
                        gap: 12,
                      }}
                    >
                      <div
                        style={{
                          fontSize: 15,
                          color: "var(--text-secondary)",
                          lineHeight: 1.7,
                        }}
                      >
                        <strong
                          style={{
                            color: "var(--text)",
                            fontWeight: 600,
                            display: "block",
                            marginBottom: 4,
                          }}
                        >
                          Gaigentic AI
                        </strong>
                        Email:{" "}
                        <a
                          href="mailto:cto@gaigentic.ai"
                          style={{
                            color: "var(--primary)",
                            textDecoration: "none",
                          }}
                        >
                          cto@gaigentic.ai
                        </a>
                      </div>
                      <div
                        style={{
                          fontSize: 15,
                          color: "var(--text-secondary)",
                          lineHeight: 1.7,
                        }}
                      >
                        Website:{" "}
                        <a
                          href="https://argusai.xyz"
                          style={{
                            color: "var(--primary)",
                            textDecoration: "none",
                          }}
                        >
                          argusai.xyz
                        </a>
                      </div>
                      <p
                        style={{
                          fontSize: 14,
                          color: "var(--text-muted)",
                          margin: "8px 0 0",
                          lineHeight: 1.6,
                        }}
                      >
                        We aim to respond to all privacy-related inquiries
                        within 10 business days.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </AnimateIn>
          ))}

          {/* ---- FOOTER NOTE ---- */}
          <AnimateIn delay={0.4}>
            <div
              style={{
                marginTop: 32,
                paddingTop: 32,
                borderTop: "1px solid var(--border)",
              }}
            >
              <p
                style={{
                  fontSize: 13,
                  color: "var(--text-muted)",
                  lineHeight: 1.7,
                  textAlign: "center",
                }}
              >
                This Privacy Policy is effective as of March 11, 2026 and
                applies to the Argus platform by Gaigentic AI.
              </p>
            </div>
          </AnimateIn>
        </div>
      </section>
    </>
  );
}
