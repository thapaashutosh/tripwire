import type { FeatureName, IncidentCall } from "@/lib/data";
import { FEATURE_LABEL, featureCeiling, featureFact } from "@/lib/format";
import s from "./FeatureBreakdown.module.css";

export interface FeatureRow {
  name: FeatureName;
  value: number;
  median: number | null;
  p99: number | null;
  unusual: boolean;
}

/** Unusual = above the 99th percentile of this identity's own training calls. */
export function featureRows(call: IncidentCall, names: FeatureName[], typical: [number, number][] | null): FeatureRow[] {
  return names.map((name, k) => {
    const value = call.features[k];
    const [median, p99] = typical?.[k] ?? [null, null];
    return { name, value, median, p99, unusual: p99 !== null && value > p99 + 1e-6 };
  });
}

export function FeatureBreakdown({ rows, n }: { rows: FeatureRow[]; n: number }) {
  return (
    <ul className={s.list}>
      {rows.map((r) => {
        const max = Math.max(featureCeiling(r.name, n), r.value, r.p99 ?? 0) || 1;
        const at = (v: number) => `${Math.min(100, Math.max(0, (v / max) * 100)).toFixed(1)}%`;
        return (
          <li key={r.name} className={r.unusual ? s.unusual : s.normal}>
            <div className={s.head}>
              <span className={s.label}>{FEATURE_LABEL[r.name]}</span>
              <span className={s.status}>
                {r.unusual ? (
                  <>
                    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
                      <path d="M5 1v8M1 5h8" stroke="currentColor" strokeWidth="1.6" transform="rotate(45 5 5)" />
                    </svg>
                    Unusual
                  </>
                ) : (
                  "Normal"
                )}
              </span>
            </div>
            <p className={s.fact}>{featureFact(r.name, r.value, n)}</p>
            <div className={s.meter} aria-hidden="true">
              {r.median !== null && r.p99 !== null && (
                <span className={s.band} style={{ left: 0, width: at(r.p99) }} />
              )}
              {r.median !== null && <span className={s.median} style={{ left: at(r.median) }} />}
              <span className={s.value} style={{ left: at(r.value) }} />
            </div>
            <p className={s.nums}>
              <span className="mono num">{r.value.toFixed(2)}</span>
              {r.p99 !== null && (
                <span>
                  {" "}
                  vs. normal range up to <span className="mono num">{r.p99.toFixed(2)}</span>
                </span>
              )}
            </p>
          </li>
        );
      })}
    </ul>
  );
}
