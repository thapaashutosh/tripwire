"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function Nav({ incidentHref }: { incidentHref: string }) {
  const path = usePathname() ?? "/";
  const links = [
    { href: "/", label: "Overview", active: path === "/" },
    { href: incidentHref, label: "Incident", active: path.startsWith("/incidents") },
    { href: "/identities/", label: "Identities", active: path.startsWith("/identities") },
    { href: "/evaluation/", label: "Evaluation", active: path.startsWith("/evaluation") },
    { href: "/how-it-works/", label: "How it works", active: path.startsWith("/how-it-works") },
  ];
  return (
    <nav className="nav" aria-label="Main">
      {links.map((l) => (
        <Link key={l.label} href={l.href} aria-current={l.active ? "page" : undefined}>
          {l.label}
        </Link>
      ))}
    </nav>
  );
}
