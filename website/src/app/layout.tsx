import type { Metadata } from "next";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { Navbar } from "@/components/navbar";
import { Footer } from "@/components/footer";

export const metadata: Metadata = {
  title: "Argus — AI-Powered Threat Intelligence Platform",
  description:
    "Real-time global threat monitoring, agentic AI triage, dark web intelligence, and 10+ integrated security tools. See every threat. Respond before impact.",
  openGraph: {
    title: "Argus — AI-Powered Threat Intelligence Platform",
    description: "Real-time global threat monitoring with agentic AI.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <body>
        <ThemeProvider>
          <Navbar />
          <main>{children}</main>
          <Footer />
        </ThemeProvider>
      </body>
    </html>
  );
}
