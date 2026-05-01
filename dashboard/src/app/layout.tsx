import type { Metadata } from "next";
import "./globals.css";
import { ToastProvider } from "@/components/shared/toast";
import { AuthProvider } from "@/components/auth/auth-provider";
import { LocaleProvider } from "@/components/locale-provider";
import { AppShell } from "@/components/layout/app-shell";

export const metadata: Metadata = {
  title: "Argus — Threat Intelligence",
  description: "Agentic Dark Web Monitoring & Threat Intelligence Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="antialiased">
        <ToastProvider>
          <AuthProvider>
            <LocaleProvider>
              <AppShell>{children}</AppShell>
            </LocaleProvider>
          </AuthProvider>
        </ToastProvider>
      </body>
    </html>
  );
}
