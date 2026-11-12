// Types for web/data/snapshot.json, written by `python -m scripts.export_web`.
// Keep in sync with scripts/export_web.py.
import raw from "@/data/snapshot.json";

export type Severity = "HIGH" | "MEDIUM" | "LOW";

export type FeatureName =
  | "api_rarity"
  | "ip_rarity"
  | "region_rarity"
  | "ua_rarity"
  | "hour_rarity"
  | "burst"
  | "error_burst";

export interface Run {
  seed: number;
  trees: number;
  fp_budget: number;
  features: FeatureName[];
  normal_events: number;
  attack_events: number;
  caught: number;
  false_positives: number;
  /** minutes into the test week */
  attack_start: number;
  global_threshold: number;
  /** shared bins for every score histogram */
  score_bins: { lo: number; hi: number; n: number };
}

export interface Identity {
  name: string;
  own_forest: boolean;
  threshold: number;
  train_events: number;
  test_events: number;
  apis: [string, number][];
  ips: [string, number][];
  regions: [string, number][];
  uas: [string, number][];
  /** 24 counts, one per UTC hour, training week */
  hours: number[];
  /** training-week scores, binned with run.score_bins: the distribution the threshold was cut from */
  train_score_hist: number[];
  /** test-week scores, same bins */
  test_score_hist: number[];
  /** per feature [median, 99th percentile] over the identity's training calls */
  feature_typical: [number, number][] | null;
}

export interface IncidentCall {
  /** minutes into the test week */
  t: number;
  api: string;
  region: string;
  ua: string;
  error: boolean;
  key_id: string;
  score: number;
  threshold: number;
  /** same order as Run.features */
  features: number[];
  /** ground truth from the simulator, never seen by the detector */
  attack: boolean;
  /** [technique id, technique name] */
  technique: [string, string] | null;
}

export interface Technique {
  id: string;
  api: string;
  denied: boolean;
  name: string;
}

export interface Incident {
  id: number;
  key: string;
  identity: string;
  ip: string;
  severity: Severity;
  new_ip: boolean;
  new_regions: string[];
  new_ua: boolean;
  techniques: Technique[];
  key_ids: string[];
  facts: string;
  action: string;
  slack_text: string;
  attack: boolean;
  events: IncidentCall[];
}

/** [minutes into test week, identity index, score, incident id or -1, attack 0|1] */
export type Point = [number, number, number, number, number];

export interface EvalRun {
  seed: number;
  normal_events: number;
  attack_events: number;
  caught: number;
  false_positives: number;
  fp_rate: number;
  incidents: number;
  attack_incidents: number;
  attack_severity: Severity | null;
  train_seconds: number;
  score_ms_per_event: number;
}

export interface Snapshot {
  run: Run;
  identities: Identity[];
  incidents: Incident[];
  points: Point[];
  eval: {
    config: { seeds: number; trees: number; fp_budget: number };
    runs: EvalRun[];
    summary: { recall_min: number; fp_rate_mean: number; fp_rate_max: number };
  } | null;
}

export const snapshot = raw as unknown as Snapshot;

export function getIncident(id: number): Incident | undefined {
  return snapshot.incidents.find((i) => i.id === id);
}

export function getIdentity(name: string): Identity | undefined {
  return snapshot.identities.find((i) => i.name === name);
}

/** The pipeline already sorts incidents by severity then size, so the first one is what on-call sees first. */
export const topIncident = snapshot.incidents[0];

export const totals = (() => {
  const { run, incidents, points } = snapshot;
  const flagged = points.filter((p) => p[3] >= 0).length;
  const bySeverity = { HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<Severity, number>;
  incidents.forEach((i) => bySeverity[i.severity]++);
  return {
    scored: points.length,
    flagged,
    incidents: incidents.length,
    bySeverity,
    falseIncidents: incidents.filter((i) => !i.attack).length,
    caught: run.caught,
    attackCalls: run.attack_events,
    falsePositives: run.false_positives,
    normalCalls: run.normal_events,
  };
})();

export const thresholdOf = new Map(snapshot.identities.map((i, k) => [k, i.threshold]));
