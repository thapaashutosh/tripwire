import type { FeatureName, Incident } from "./data";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
export const DAY_NAMES = DAYS;
export const WEEK_MIN = 7 * 1440;

const pad = (n: number) => String(n).padStart(2, "0");

/** Minutes into the replayed week -> "Fri 03:12". All times are UTC. */
export function weekTime(t: number, seconds = false): string {
  const day = Math.floor(t / 1440);
  const m = t - day * 1440;
  const hh = Math.floor(m / 60);
  const mm = Math.floor(m % 60);
  const ss = Math.floor((m * 60) % 60);
  return `${DAYS[day] ?? `Day ${day + 1}`} ${pad(hh)}:${pad(mm)}${seconds ? `:${pad(ss)}` : ""}`;
}

/** minutes -> "+2:23" */
export function offset(minutes: number): string {
  const s = Math.round(minutes * 60);
  return `+${Math.floor(s / 60)}:${pad(s % 60)}`;
}

export function duration(minutes: number): string {
  if (minutes < 1) return `${Math.round(minutes * 60)} s`;
  if (minutes < 90) return `${minutes.toFixed(minutes < 10 ? 1 : 0)} min`;
  return `${(minutes / 60).toFixed(1)} h`;
}

export const pct = (x: number, digits = 2) => `${(x * 100).toFixed(digits)}%`;
export const num = (n: number) => n.toLocaleString("en-US");
export const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`;

export function span(inc: Incident) {
  return inc.events[inc.events.length - 1].t - inc.events[0].t;
}

/** "svc-reporting's access key was used from a new IP: 9 calls in 6 minutes" */
export function headline(inc: Incident): string {
  const who = `${inc.identity}'s ${inc.key_ids.length ? "access key" : "role"}`;
  const where = inc.new_ip ? "a new IP" : inc.ip;
  const n = inc.events.length;
  const mins = Math.max(1, Math.round(span(inc)));
  return n > 1
    ? `${who} was used from ${where}: ${n} calls in ${mins} minute${mins === 1 ? "" : "s"}`
    : `${who} made one unusual call from ${where}`;
}

export const FEATURE_LABEL: Record<FeatureName, string> = {
  api_rarity: "API",
  ip_rarity: "Source IP",
  region_rarity: "Region",
  ua_rarity: "User agent",
  hour_rarity: "Hour of day",
  burst: "Call rate",
  error_burst: "Errors",
};

export const FEATURE_CATCHES: Record<FeatureName, string> = {
  api_rarity: "A reporting job calling CreateAccessKey",
  ip_rarity: "A source IP this key has never used",
  region_rarity: "Instances launched in a region you don't use",
  ua_rarity: "aws-cli on Kali instead of the job's usual boto3",
  hour_rarity: "3am activity from a 9 to 5 identity",
  burst: "9 calls in 6 minutes from a key that makes 4 an hour",
  error_burst: "AccessDenied after AccessDenied while someone probes permissions",
};

/**
 * Turn a raw feature value back into the plain fact it encodes, by inverting the formulas in
 * tripwire/features.py (scored at runtime, so no leave-one-out correction):
 *   rarity      = -ln((c + 1) / (n + 1))              -> c = (n + 1)e^-r - 1
 *   hour_rarity = -ln((smooth + 0.5) / (n + 12))      -> smooth = (n + 12)e^-r - 0.5
 *   burst       = ln(1 + calls in last 10 min)
 */
export function featureFact(name: FeatureName, value: number, n: number): string {
  if (name === "burst" || name === "error_burst") {
    const c = Math.max(0, Math.round(Math.expm1(value)));
    if (name === "error_burst") return c === 0 ? "no failed calls in the last 10 min" : `${plural(c, "failed call")} in the last 10 min`;
    return `${plural(c, "call")} in the last 10 min`;
  }
  if (name === "hour_rarity") {
    const share = Math.max(0, (n + 12) * Math.exp(-value) - 0.5) / n;
    return share < 0.001 ? "almost never active at this hour" : `${pct(share, 1)} of its calls fall near this hour`;
  }
  const c = Math.max(0, Math.round((n + 1) * Math.exp(-value) - 1));
  return c === 0 ? "never seen in training" : `seen ${num(c)} of ${num(n)} times in training`;
}

/** Largest value the feature can take for an identity with n training calls, for scaling bars. */
export function featureCeiling(name: FeatureName, n: number): number {
  if (name === "hour_rarity") return Math.log((n + 12) / 0.5);
  if (name === "burst" || name === "error_burst") return Math.log1p(12);
  return Math.log(n + 1);
}
