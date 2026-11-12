import Link from "next/link";
import { snapshot, thresholdOf, topIncident } from "@/lib/data";
import { DAY_NAMES, WEEK_MIN, weekTime } from "@/lib/format";
import { Sev } from "./Badges";
import s from "./WeekTimeline.module.css";

/**
 * Every scored call of the week on one axis: x is time, y is how far the call's score sits above or
 * below its own identity's threshold. Putting every identity on the same "distance to threshold" scale
 * means one line separates flagged from normal for all of them.
 */
export function WeekTimeline() {
  const { points, incidents } = snapshot;
  const sevOf = new Map(incidents.map((i) => [i.id, i.severity]));
  const delta = (p: (typeof points)[number]) => p[2] - (thresholdOf.get(p[1]) ?? 0);

  const ds = points.map(delta);
  const lo = Math.min(...ds) - 0.01;
  const hi = Math.max(...ds) + 0.015;
  const X = (t: number) => (t / WEEK_MIN) * 1000;
  // Piecewise scale: the area above the threshold gets TOP of the height so flagged calls are not squeezed
  // into a sliver. Stated in the caption on the overview page.
  const TOP = 0.3;
  const Y = (d: number) => (d >= 0 ? TOP * 100 * (1 - d / hi) : TOP * 100 + (1 - TOP) * 100 * (d / lo));
  const zeroPct = Y(0);

  const normal = points.filter((p) => p[3] < 0);
  const flagged = points.filter((p) => p[3] >= 0);
  const high = flagged.filter((p) => sevOf.get(p[3]) === "HIGH");
  const other = flagged.filter((p) => sevOf.get(p[3]) !== "HIGH");
  const path = (ps: typeof points) => ps.map((p) => `M${X(p[0]).toFixed(1)} ${Y(delta(p)).toFixed(2)}h0`).join("");

  const top = topIncident;
  const topPts = flagged.filter((p) => p[3] === top.id);
  const calloutX = (X(top.events[0].t) / 1000) * 100;
  const calloutY = Math.min(...topPts.map((p) => Y(delta(p))));
  const labelLeft = calloutX > 55;

  return (
    <figure className={s.fig}>
      <Link href={`/incidents/${top.id}/`} className={s.calloutStatic}>
        <Sev level={top.severity} />
        <span className="mono">{top.identity}</span>
        <span className="faint num">
          {top.events.length} calls · {weekTime(top.events[0].t)}
        </span>
        <span aria-hidden="true" className="faint">
          ↓ highest cluster on {weekTime(top.events[0].t).slice(0, 3)}
        </span>
      </Link>
      <div className={s.plot}>
        <div className={s.zone} style={{ height: `${zeroPct}%` }}>
          <span className={s.zoneLabel}>Above its threshold: flagged</span>
        </div>
        <div className={s.threshold} style={{ top: `${zeroPct}%` }}>
          <span>Threshold</span>
        </div>
        {DAY_NAMES.map((d, i) => (
          <div key={d} className={s.day} style={{ left: `${(i / 7) * 100}%` }}>
            <span>{d}</span>
          </div>
        ))}

        <svg viewBox="0 0 1000 100" preserveAspectRatio="none" className={s.svg} aria-hidden="true">
          <path d={path(normal)} className={s.normal} />
          {other.map((p, k) => (
            <a key={`o${k}`} href={`/incidents/${p[3]}/`} tabIndex={-1}>
              <path d={path([p])} className={s.otherRing} />
              <path d={path([p])} className={s.otherHole} />
              <title>{`${snapshot.identities[p[1]].name}  ${weekTime(p[0])}  ${sevOf.get(p[3])}`}</title>
            </a>
          ))}
          {high.map((p, k) => (
            <a key={`h${k}`} href={`/incidents/${p[3]}/`} tabIndex={-1}>
              <path d={path([p])} className={s.high} />
              <title>{`${snapshot.identities[p[1]].name}  ${weekTime(p[0])}  HIGH`}</title>
            </a>
          ))}
        </svg>

        <div
          className={`${s.callout} ${labelLeft ? s.left : s.right}`}
          style={{ left: `${calloutX}%`, top: `${calloutY}%` }}
        >
          <span className={s.leader} aria-hidden="true" />
          <Link href={`/incidents/${top.id}/`} className={s.card}>
            <Sev level={top.severity} />
            <span className="mono">{top.identity}</span>
            <span className="faint num">
              {top.events.length} calls · {weekTime(top.events[0].t)}
            </span>
          </Link>
        </div>
      </div>

      <div className={s.legend} aria-hidden="true">
        <span>
          <i className={s.kNormal} /> Normal call
        </span>
        <span>
          <i className={s.kOther} /> Flagged, MEDIUM or LOW
        </span>
        <span>
          <i className={s.kHigh} /> Flagged, HIGH
        </span>
      </div>
      <p className="sr-only">
        Scatter of {points.length} calls across the week. {flagged.length} sit above their identity&rsquo;s threshold.
        The largest group is {top.events.length} calls from {top.identity} on {weekTime(top.events[0].t)}.
      </p>
    </figure>
  );
}
