import type { Metadata, Viewport } from "next";
import Link from "next/link";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import { Nav } from "@/components/Nav";
import { snapshot, topIncident } from "@/lib/data";
import { num } from "@/lib/format";
import "./globals.css";

const sans = IBM_Plex_Sans({
  variable: "--font-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

const mono = IBM_Plex_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  weight: ["400", "500"],
});

export const metadata: Metadata = {
  title: { default: "Overview · tripwire", template: "%s · tripwire" },
  description: "Catches stolen AWS access keys in CloudTrail with one anomaly model per identity.",
};

export const viewport: Viewport = { themeColor: "#0b0d10", colorScheme: "dark" };

export default function RootLayout({ children }: LayoutProps<"/">) {
  const { run } = snapshot;
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>
        <a href="#main" className="skip">
          Skip to content
        </a>
        <header className="topbar">
          <div className="shell">
            <Link href="/" className="wordmark">
              <Mark />
              tripwire
            </Link>
            <Nav incidentHref={`/incidents/${topIncident.id}/`} />
            <span className="run-tag">Synthetic replay · seed {run.seed}</span>
          </div>
        </header>
        <main id="main">
          <div className="shell">{children}</div>
        </main>
        <footer className="foot">
          <div className="shell">
            Every number here is output from one run of the real detector on synthetic CloudTrail traffic (seed{" "}
            {run.seed}, {num(run.normal_events)} normal calls plus a {run.attack_events} call attack), exported by{" "}
            <code>scripts/export_web.py</code>.
          </div>
        </footer>
      </body>
    </html>
  );
}

/** A taut wire between two posts, tripped. */
function Mark() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true">
      <path d="M2.5 16V5M17.5 16V9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path d="M2.5 7.5h8.5l3.2 3.4" stroke="var(--ink-2)" strokeWidth="1.6" fill="none" strokeLinecap="round" />
    </svg>
  );
}
