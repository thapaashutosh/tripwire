import type { Severity } from "@/lib/data";

/** Severity is always icon + word. Only HIGH gets the accent colour. */
export function Sev({ level }: { level: Severity }) {
  return (
    <span className={`sev sev-${level}`}>
      <SevIcon level={level} />
      {level}
    </span>
  );
}

export function SevIcon({ level, size = 11 }: { level: Severity; size?: number }) {
  if (level === "HIGH")
    return (
      <svg width={size} height={size} viewBox="0 0 12 12" aria-hidden="true">
        <path d="M6 0.8 11.4 10.9H0.6Z" fill="currentColor" />
        <path d="M6 4.3v3.2" stroke="var(--bg)" strokeWidth="1.4" strokeLinecap="round" />
        <circle cx="6" cy="9.1" r="0.8" fill="var(--bg)" />
      </svg>
    );
  if (level === "MEDIUM")
    return (
      <svg width={size} height={size} viewBox="0 0 12 12" aria-hidden="true">
        <path d="M6 1 11 6 6 11 1 6Z" fill="none" stroke="currentColor" strokeWidth="1.4" />
        <path d="M6 1 11 6 6 11Z" fill="currentColor" />
      </svg>
    );
  return (
    <svg width={size} height={size} viewBox="0 0 12 12" aria-hidden="true">
      <circle cx="6" cy="6" r="4.3" fill="none" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}

export function Denied() {
  return (
    <span className="denied">
      <svg width="11" height="11" viewBox="0 0 12 12" aria-hidden="true">
        <circle cx="6" cy="6" r="4.8" fill="none" stroke="currentColor" strokeWidth="1.3" />
        <path d="M2.7 9.3 9.3 2.7" stroke="currentColor" strokeWidth="1.3" />
      </svg>
      AccessDenied
    </span>
  );
}

export function Truth({ attack }: { attack: boolean }) {
  return attack ? (
    <span className="truth truth-attack">Injected attack</span>
  ) : (
    <span className="truth truth-normal">Normal traffic</span>
  );
}
