"use client";

import { AnimateIn } from "@/components/animate-in";
import { Shield, FileText } from "lucide-react";

const SECTIONS = [
  {
    id: "acceptance",
    title: "1. Acceptance of Terms",
    content: [
      `By accessing or using the Argus platform ("Service"), operated by Gaigentic AI ("Company," "we," "us," or "our"), you ("User," "you," or "your") agree to be bound by these Terms of Service ("Terms"). If you are using the Service on behalf of an organization, you represent and warrant that you have the authority to bind that organization to these Terms, and "you" refers to both you individually and the organization.`,
      `If you do not agree to these Terms, you must not access or use the Service. Your continued use of the Service following the posting of any changes to these Terms constitutes acceptance of those changes.`,
      `These Terms apply to all visitors, registered users, and any other persons who access or use the Service, including via API integrations, automated scripts, or third-party applications.`,
    ],
  },
  {
    id: "service",
    title: "2. Description of Service",
    content: [
      `Argus is an AI-powered threat intelligence platform that provides real-time cybersecurity monitoring, analysis, and alerting capabilities. The Service includes, but is not limited to:`,
    ],
    list: [
      "Aggregation and correlation of data from 30+ open-source and proprietary threat intelligence feeds",
      "AI-driven threat triage, classification, and prioritization using agentic AI systems",
      "Global threat landscape monitoring across 190+ countries",
      "Dark web monitoring and reconnaissance capabilities",
      "Automated vulnerability scanning and detection through integrated security tools (including OpenCTI, Wazuh, Nuclei, Suricata, and others)",
      "Security Orchestration, Automation, and Response (SOAR) workflows",
      "Real-time alerting via email, webhook, Slack, and other notification channels",
      "Threat intelligence reports, dashboards, and data export functionality",
      "API access for programmatic integration with your existing security infrastructure",
    ],
    contentAfter: [
      `The specific features available to you depend on your subscription tier. We reserve the right to modify, suspend, or discontinue any part of the Service at any time, with reasonable notice where practicable.`,
    ],
  },
  {
    id: "account",
    title: "3. Account Registration & Security",
    content: [
      `To use certain features of the Service, you must register for an account. When registering, you agree to:`,
    ],
    list: [
      "Provide accurate, current, and complete registration information",
      "Maintain and promptly update your account information to keep it accurate and current",
      "Maintain the confidentiality of your account credentials, including passwords and API keys",
      "Accept responsibility for all activities that occur under your account",
      "Immediately notify us at cto@gaigentic.ai if you become aware of any unauthorized use of your account or any other breach of security",
    ],
    contentAfter: [
      `You must be at least 18 years of age to create an account. We reserve the right to suspend or terminate accounts that we reasonably believe have been compromised, are being used fraudulently, or are in violation of these Terms.`,
      `You are responsible for ensuring that your use of the Service complies with all applicable laws and regulations, including but not limited to data protection and export control laws. Multi-factor authentication is strongly recommended for all accounts and may be required for certain subscription tiers.`,
    ],
  },
  {
    id: "acceptable-use",
    title: "4. Acceptable Use",
    content: [
      `You agree to use the Service only for lawful purposes and in accordance with these Terms. You expressly agree not to:`,
    ],
    list: [
      "Use the Service to engage in, facilitate, or support any illegal activity, including unauthorized access to computer systems, networks, or data",
      "Reverse engineer, decompile, disassemble, or otherwise attempt to derive the source code of the Service, its algorithms, or underlying AI models",
      "Abuse, overload, or disrupt the Service or its infrastructure, including through denial-of-service attacks, excessive API calls beyond your rate limits, or automated scraping",
      "Redistribute, resell, sublicense, or commercially exploit threat intelligence data obtained through the Service without prior written authorization from Gaigentic AI",
      "Use the Service to develop a competing product or service",
      "Upload malicious code, malware, or any content designed to compromise the security or integrity of the Service",
      "Impersonate any person or entity, or misrepresent your affiliation with any person or entity",
      "Use threat intelligence data obtained through the Service to conduct offensive cyber operations, harassment, or any activity that could cause harm to individuals or organizations",
      "Share your account credentials or API keys with unauthorized third parties",
      "Circumvent or attempt to circumvent any access controls, rate limits, or usage restrictions",
    ],
    contentAfter: [
      `Responsible Disclosure: If you discover a security vulnerability in the Argus platform, we ask that you report it to us responsibly at cto@gaigentic.ai before disclosing it publicly. We commit to acknowledging your report within 48 hours and providing a timeline for remediation. We will not take legal action against researchers who discover and report vulnerabilities in good faith, provided they do not access, modify, or delete other users' data, and they allow us a reasonable period to address the issue before public disclosure.`,
    ],
  },
  {
    id: "ip",
    title: "5. Intellectual Property",
    content: [
      `Ownership of the Service: The Service, including its software, AI models, algorithms, user interface, documentation, branding, trademarks, and all related intellectual property, is and remains the exclusive property of Gaigentic AI and its licensors. These Terms do not grant you any ownership rights in the Service. The Argus name, logo, and all related product names and marks are trademarks of Gaigentic AI.`,
      `Ownership of Your Data: You retain all rights, title, and interest in the data you upload to or generate through the Service ("User Data"), including threat intelligence reports generated from your specific organizational data, custom detection rules, and configurations. We do not claim ownership of your User Data.`,
      `License to User Data: By using the Service, you grant Gaigentic AI a limited, non-exclusive, worldwide license to process, store, and analyze your User Data solely for the purpose of providing and improving the Service. This license terminates when you delete your User Data or close your account, subject to any retention periods required by law or specified in these Terms.`,
      `Aggregated Data: We may collect and use aggregated, anonymized, and de-identified data derived from your use of the Service for purposes of improving the Service, conducting research, and generating industry-level threat intelligence. Such aggregated data will not identify you or any individual and is not considered User Data.`,
      `Open-Source Components: The Service integrates with and builds upon open-source security tools. The use of such components is governed by their respective open-source licenses, and nothing in these Terms restricts any rights you may have under those licenses.`,
    ],
  },
  {
    id: "payment",
    title: "6. Subscription & Payment",
    content: [
      `The Service is offered across multiple subscription tiers, including a free Community tier and paid plans (Professional and Enterprise). Current pricing and feature details are available on our pricing page at argusai.xyz/pricing.`,
      `Free Tier: The Community plan is provided at no cost and includes a limited set of features as described on the pricing page. We reserve the right to modify the scope of the free tier at any time with 30 days' prior notice.`,
      `Paid Plans: Paid subscriptions are billed on a monthly or annual basis, as selected at the time of purchase. All fees are quoted in U.S. dollars unless otherwise stated. You authorize us to charge your designated payment method for all applicable fees.`,
      `Renewals: Paid subscriptions automatically renew at the end of each billing cycle unless you cancel before the renewal date. We will notify you at least 14 days before a renewal at a different price.`,
      `Price Changes: We may change our pricing at any time. For existing subscribers, price changes will take effect at the start of the next billing cycle following at least 30 days' notice. If you do not agree with a price change, you may cancel your subscription before the new price takes effect.`,
      `Refunds: Except where required by applicable law, fees are non-refundable once charged. If you cancel a paid subscription, you will retain access to paid features until the end of your current billing period.`,
      `Taxes: All fees are exclusive of applicable taxes. You are responsible for any taxes, duties, or levies imposed by your jurisdiction in connection with your use of the Service.`,
    ],
  },
  {
    id: "availability",
    title: "7. Service Availability",
    content: [
      `We strive to maintain high availability of the Service and will make commercially reasonable efforts to ensure uptime. However, the Service is provided on a "best effort" basis and we do not guarantee uninterrupted or error-free operation.`,
      `Planned Maintenance: We may perform scheduled maintenance that could result in temporary service interruptions. We will provide at least 24 hours' advance notice for planned maintenance windows via our status page and email notifications. Whenever possible, maintenance will be scheduled during off-peak hours.`,
      `Unplanned Outages: In the event of unplanned outages, we will use commercially reasonable efforts to restore the Service as quickly as possible and will provide timely updates through our status page.`,
      `Service Level Agreements: Enterprise customers may negotiate specific SLAs with guaranteed uptime percentages and remedies. Such SLAs, where applicable, will be documented in a separate agreement and will take precedence over this section.`,
      `Third-Party Dependencies: The Service relies on third-party threat intelligence feeds, cloud infrastructure providers, and open-source tools. We are not responsible for disruptions caused by the unavailability or changes to these third-party services, though we will work to mitigate any impact on your experience.`,
    ],
  },
  {
    id: "liability",
    title: "8. Limitation of Liability",
    content: [
      `TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL GAIGENTIC AI, ITS DIRECTORS, OFFICERS, EMPLOYEES, AGENTS, AFFILIATES, OR LICENSORS BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING BUT NOT LIMITED TO LOSS OF PROFITS, DATA, BUSINESS OPPORTUNITIES, OR GOODWILL, ARISING OUT OF OR IN CONNECTION WITH YOUR USE OF OR INABILITY TO USE THE SERVICE, EVEN IF WE HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.`,
      `TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, OUR TOTAL AGGREGATE LIABILITY FOR ALL CLAIMS ARISING OUT OF OR RELATING TO THESE TERMS OR THE SERVICE SHALL NOT EXCEED THE GREATER OF: (A) THE TOTAL AMOUNT YOU PAID TO US IN THE TWELVE (12) MONTHS IMMEDIATELY PRECEDING THE EVENT GIVING RISE TO THE CLAIM, OR (B) ONE HUNDRED U.S. DOLLARS ($100).`,
      `The Service provides threat intelligence and security information for informational and analytical purposes. It is not a substitute for professional cybersecurity services, incident response, or legal advice. You acknowledge that no threat intelligence platform can guarantee the detection of all threats, and you agree not to hold Gaigentic AI liable for any security incident that the Service fails to detect or prevent.`,
      `Some jurisdictions do not allow the exclusion or limitation of certain damages. In such jurisdictions, our liability will be limited to the greatest extent permitted by law.`,
    ],
  },
  {
    id: "indemnification",
    title: "9. Indemnification",
    content: [
      `You agree to indemnify, defend, and hold harmless Gaigentic AI and its officers, directors, employees, agents, affiliates, successors, and assigns from and against any and all claims, liabilities, damages, losses, costs, and expenses (including reasonable attorneys' fees and court costs) arising out of or relating to:`,
    ],
    list: [
      "Your use or misuse of the Service",
      "Your violation of these Terms or any applicable law or regulation",
      "Your violation of any third-party rights, including intellectual property, privacy, or contractual rights",
      "Any data or content you submit to or transmit through the Service",
      "Any actions taken by you or your authorized users based on threat intelligence provided by the Service",
    ],
    contentAfter: [
      `We reserve the right, at our own expense, to assume the exclusive defense and control of any matter otherwise subject to indemnification by you. In such cases, you agree to cooperate with us in asserting any available defenses.`,
    ],
  },
  {
    id: "termination",
    title: "10. Termination",
    content: [
      `Termination by You: You may terminate your account and stop using the Service at any time by contacting us at cto@gaigentic.ai or through your account settings. Upon termination, your right to access the Service will cease immediately, except as provided below regarding data export.`,
      `Termination by Us: We may suspend or terminate your access to the Service immediately, without prior notice or liability, if we reasonably believe that you have violated these Terms, engaged in fraudulent or illegal activity, or if continued provision of the Service to you is no longer commercially viable. For terminations not caused by your breach, we will provide at least 30 days' notice.`,
      `Data Export: Following termination, we will make your User Data available for export for a period of 30 days. After this export period, we reserve the right to delete your User Data from our systems, unless retention is required by applicable law.`,
      `Survival: The following sections shall survive termination of these Terms: Intellectual Property (Section 5), Limitation of Liability (Section 8), Indemnification (Section 9), Governing Law (Section 11), and any other provisions that by their nature are intended to survive termination.`,
      `Effect on Paid Subscriptions: If we terminate your account for reasons other than your breach of these Terms, we will provide a pro-rata refund of any prepaid fees for the unused portion of your subscription period.`,
    ],
  },
  {
    id: "governing-law",
    title: "11. Governing Law",
    content: [
      `These Terms shall be governed by and construed in accordance with the laws of the State of Delaware, United States, without regard to its conflict of laws principles.`,
      `Any disputes arising out of or relating to these Terms or the Service shall first be attempted to be resolved through good-faith negotiation between the parties for a period of at least 30 days. If the dispute cannot be resolved through negotiation, it shall be submitted to binding arbitration in accordance with the rules of the American Arbitration Association, conducted in English. The arbitration shall take place in Wilmington, Delaware, or remotely at the election of either party.`,
      `Notwithstanding the foregoing, either party may seek injunctive or other equitable relief in any court of competent jurisdiction to prevent the actual or threatened infringement or misappropriation of intellectual property rights.`,
      `If any provision of these Terms is found to be unenforceable or invalid, that provision shall be limited or eliminated to the minimum extent necessary, and the remaining provisions shall remain in full force and effect.`,
    ],
  },
  {
    id: "changes",
    title: "12. Changes to Terms",
    content: [
      `We reserve the right to modify these Terms at any time. When we make material changes, we will provide notice through one or more of the following methods: a prominent notice on the Service, an email to the address associated with your account, or a notification in your account dashboard.`,
      `Material changes will become effective 30 days after notice is provided, unless the changes are required by law, in which case they may take effect immediately. Non-material changes (such as typographical corrections or clarifications) may take effect immediately upon posting.`,
      `Your continued use of the Service after the effective date of any changes constitutes your acceptance of the revised Terms. If you do not agree to the revised Terms, you must stop using the Service and may terminate your account as provided in Section 10.`,
      `We will maintain an archive of previous versions of these Terms, which will be available upon request.`,
    ],
  },
  {
    id: "contact",
    title: "13. Contact",
    content: [
      `If you have any questions, concerns, or feedback regarding these Terms of Service, please contact us at:`,
    ],
    contactInfo: true,
  },
];

export default function TermsPage() {
  return (
    <>
      {/* ═══════════════════ HERO ═══════════════════ */}
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
              <FileText size={14} style={{ color: "var(--primary)" }} />
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
              Terms of{" "}
              <span className="gradient-text">Service</span>
            </h1>
          </AnimateIn>

          <AnimateIn delay={0.35}>
            <p
              style={{
                fontSize: "clamp(15px, 1.8vw, 18px)",
                lineHeight: 1.6,
                color: "rgba(244,246,248,0.6)",
                maxWidth: 560,
                margin: "0 auto",
              }}
            >
              Please read these terms carefully before using the Argus platform.
              By accessing or using our Service, you agree to be bound by these
              terms.
            </p>
          </AnimateIn>

          <AnimateIn delay={0.45}>
            <p
              style={{
                fontSize: 14,
                color: "var(--text-muted)",
                marginTop: 24,
                fontWeight: 500,
              }}
            >
              Last updated: March 11, 2026
            </p>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ TABLE OF CONTENTS ═══════════════════ */}
      <section
        style={{
          padding: "60px 0 0",
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
                padding: "32px 36px",
                borderRadius: 16,
                border: "1px solid var(--border)",
                background: "var(--bg-card)",
              }}
            >
              <h2
                style={{
                  fontSize: 16,
                  fontWeight: 600,
                  color: "var(--text)",
                  marginBottom: 20,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                }}
              >
                Table of Contents
              </h2>
              <nav
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 10,
                }}
              >
                {SECTIONS.map((section) => (
                  <a
                    key={section.id}
                    href={`#${section.id}`}
                    style={{
                      fontSize: 15,
                      color: "var(--text-secondary)",
                      textDecoration: "none",
                      transition: "color 0.2s",
                      lineHeight: 1.5,
                    }}
                    onMouseEnter={(e) =>
                      (e.currentTarget.style.color = "var(--primary)")
                    }
                    onMouseLeave={(e) =>
                      (e.currentTarget.style.color = "var(--text-secondary)")
                    }
                  >
                    {section.title}
                  </a>
                ))}
              </nav>
            </div>
          </AnimateIn>
        </div>
      </section>

      {/* ═══════════════════ CONTENT ═══════════════════ */}
      <section
        style={{
          padding: "60px 0 120px",
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
          {SECTIONS.map((section, i) => (
            <AnimateIn key={section.id} delay={0.05 * i}>
              <div
                id={section.id}
                style={{
                  scrollMarginTop: 100,
                  marginBottom: 56,
                  paddingBottom: 56,
                  borderBottom:
                    i < SECTIONS.length - 1
                      ? "1px solid var(--border)"
                      : "none",
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
                  }}
                >
                  {section.title}
                </h2>

                {section.content.map((paragraph, pi) => (
                  <p
                    key={pi}
                    style={{
                      fontSize: 15,
                      lineHeight: 1.8,
                      color: "var(--text-secondary)",
                      marginBottom: 16,
                    }}
                  >
                    {paragraph}
                  </p>
                ))}

                {section.list && (
                  <ul
                    style={{
                      margin: "16px 0",
                      paddingLeft: 24,
                      display: "flex",
                      flexDirection: "column",
                      gap: 10,
                    }}
                  >
                    {section.list.map((item, li) => (
                      <li
                        key={li}
                        style={{
                          fontSize: 15,
                          lineHeight: 1.7,
                          color: "var(--text-secondary)",
                        }}
                      >
                        {item}
                      </li>
                    ))}
                  </ul>
                )}

                {section.contentAfter?.map((paragraph, pi) => (
                  <p
                    key={`after-${pi}`}
                    style={{
                      fontSize: 15,
                      lineHeight: 1.8,
                      color: "var(--text-secondary)",
                      marginBottom: 16,
                      marginTop: pi === 0 ? 16 : 0,
                    }}
                  >
                    {paragraph}
                  </p>
                ))}

                {section.contactInfo && (
                  <div
                    style={{
                      marginTop: 24,
                      padding: "28px 32px",
                      borderRadius: 14,
                      border: "1px solid var(--border)",
                      background: "var(--bg-card)",
                      display: "flex",
                      flexDirection: "column",
                      gap: 16,
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <Shield size={20} style={{ color: "var(--primary)", flexShrink: 0 }} />
                      <div>
                        <div
                          style={{
                            fontSize: 15,
                            fontWeight: 600,
                            color: "var(--text)",
                            marginBottom: 2,
                          }}
                        >
                          Gaigentic AI
                        </div>
                        <div
                          style={{
                            fontSize: 14,
                            color: "var(--text-muted)",
                          }}
                        >
                          Argus Threat Intelligence Platform
                        </div>
                      </div>
                    </div>

                    <div
                      style={{
                        height: 1,
                        background: "var(--border)",
                      }}
                    />

                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: 10,
                      }}
                    >
                      <div
                        style={{
                          fontSize: 14,
                          color: "var(--text-secondary)",
                          lineHeight: 1.6,
                        }}
                      >
                        <span style={{ fontWeight: 600, color: "var(--text)" }}>
                          Email:{" "}
                        </span>
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
                          fontSize: 14,
                          color: "var(--text-secondary)",
                          lineHeight: 1.6,
                        }}
                      >
                        <span style={{ fontWeight: 600, color: "var(--text)" }}>
                          Website:{" "}
                        </span>
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
                      <div
                        style={{
                          fontSize: 14,
                          color: "var(--text-secondary)",
                          lineHeight: 1.6,
                        }}
                      >
                        <span style={{ fontWeight: 600, color: "var(--text)" }}>
                          Security vulnerabilities:{" "}
                        </span>
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
                    </div>

                    <div
                      style={{
                        height: 1,
                        background: "var(--border)",
                      }}
                    />

                    <p
                      style={{
                        fontSize: 14,
                        lineHeight: 1.7,
                        color: "var(--text-muted)",
                      }}
                    >
                      We aim to respond to all inquiries within two (2) business
                      days. For urgent security matters, please include
                      &ldquo;URGENT&rdquo; in your subject line.
                    </p>
                  </div>
                )}
              </div>
            </AnimateIn>
          ))}
        </div>
      </section>
    </>
  );
}
