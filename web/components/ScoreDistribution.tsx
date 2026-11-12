import { snapshot, type Identity, type Severity } from "@/lib/data";
import { weekTime } from "@/lib/format";
import s from "./ScoreDistribution.module.css";

/**
 * Histogram of an identity's training scores (what its threshold was cut from), with this week's
 * flagged calls stacked above on the same x axis.
 */
export function ScoreDistribution({ ident, index }: { ident: Identity; index: number }) {
  const { lo, hi, n } = snapshot.run.score_bins;
  const counts = ident.train_score_hist;
  const max = Math.max(...counts, 1);
  const xPct = (v: number) => ((v - lo) / (hi - lo)) * 100;
  const sevOf = new Map(snapshot.incidents.map((i) => [i.id, i.severity]));

  const flagged = snapshot.points
    .filter((p) => p[1] === index && p[3] >= 0)
    .map((p) => ({ t: p[0], score: p[2], sev: sevOf.get(p[3]) as Severity, inc: p[3] }))
    .sort((a, b) => a.score - b.score);

  // stack markers that share a bin so they don't overlap
  const stackOf = new Map<number, number>();
  const placed = flagged.map((f) => {
    const bin = Math.min(n - 1, Math.floor(((f.score - lo) / (hi - lo)) * n));
    const k = stackOf.get(bin) ?? 0;
    stackOf.set(bin, k + 1);
    return { ...f, bin, k };
  });
  const rows = Math.max(1, ...Array.from(stackOf.values()));

  return (
    <figure className={s.fig}>
      <div className={s.markers} style={{ height: `${Math.max(rows * 13 + 8, 30)}px` }}>
        <span className={s.markersLabel}>This week&rsquo;s flagged calls{flagged.length === 0 && ": none"}</span>
        {placed.map((f, i) => (
          <a
            key={i}
            href={`/incidents/${f.inc}/`}
            tabIndex={-1}
            className={`${s.mark} ${f.sev === "HIGH" ? s.markHigh : s.markOther}`}
            style={{ left: `${((f.bin + 0.5) / n) * 100}%`, bottom: `${4 + f.k * 13}px` }}
            title={`${weekTime(f.t)}  score ${f.score.toFixed(3)}  ${f.sev}`}
          />
        ))}
      </div>

      <div className={s.plot}>
        <svg viewBox={`0 0 ${n} 100`} preserveAspectRatio="none" className={s.svg} aria-hidden="true">
          {counts.map((c, i) => {
            const h = c ? Math.max((c / max) * 100, 1.5) : 0;
            return <rect key={i} x={i + 0.12} width={0.76} y={100 - h} height={h} className={s.bar} />;
          })}
        </svg>
        <div className={s.threshold} style={{ left: `${xPct(ident.threshold)}%` }}>
          <span>threshold {ident.threshold.toFixed(3)}</span>
        </div>
      </div>

      <div className={s.axis} aria-hidden="true">
        <span className="num">{lo.toFixed(2)}</span>
        <span>anomaly score →</span>
        <span className="num">{hi.toFixed(2)}</span>
      </div>
    </figure>
  );
}
