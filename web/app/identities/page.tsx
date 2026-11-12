import type { Metadata } from "next";
import Link from "next/link";
import { Sev } from "@/components/Badges";
import { ScoreDistribution } from "@/components/ScoreDistribution";
import { snapshot, type Identity } from "@/lib/data";
import { num, pct, plural } from "@/lib/format";
import s from "./identities.module.css";

export const metadata: Metadata = { title: "Identities" };

export default function IdentitiesPage() {
  const { points, incidents, run } = snapshot;
  const sevOf = new Map(incidents.map((i) => [i.id, i.severity]));

  const rows = snapshot.identities.map((ident, index) => {
    const mine = points.filter((p) => p[1] === index);
    const flagged = mine.filter((p) => p[3] >= 0);
    const high = flagged.filter((p) => sevOf.get(p[3]) === "HIGH");
    return { ident, index, flagged, high };
  });
  // the identity with the most HIGH calls first: that's where a reader should look
  rows.sort((a, b) => b.high.length - a.high.length || b.flagged.length - a.flagged.length);

  return (
    <>
      <div className="page-head">
        <h1>Identities</h1>
        <p>
          Every identity gets its own model, trained on one week of its own calls. Its threshold is the 99.7th percentile
          of its own training scores, so roughly 3 in 1,000 normal calls are expected to cross it. The baseline is only
          rebuilt by <code>scripts/train.py</code>, never from live traffic, so an attacker can&rsquo;t slowly teach it
          that they are normal.
        </p>
      </div>

      <nav className={s.jump} aria-label="Jump to identity">
        {rows.map(({ ident, flagged }) => (
          <a key={ident.name} href={`#${ident.name}`}>
            <span className="mono">{ident.name}</span>
            <span className="faint num">{flagged.length} flagged</span>
          </a>
        ))}
      </nav>

      {rows.map(({ ident, index, flagged, high }) => (
        <IdentityBlock key={ident.name} ident={ident} index={index} flagged={flagged.length} high={high.map((p) => p[2])} />
      ))}

      <p className="caption" style={{ marginTop: 28 }}>
        Scores are on a shared axis from {run.score_bins.lo.toFixed(2)} to {run.score_bins.hi.toFixed(2)}. Higher means
        the call was easier to isolate from the identity&rsquo;s history.
      </p>
    </>
  );
}

function IdentityBlock({ ident, index, flagged, high }: { ident: Identity; index: number; flagged: number; high: number[] }) {
  const { lo, hi, n } = snapshot.run.score_bins;
  const lastTrainBin = ident.train_score_hist.findLastIndex((c) => c > 0);
  const trainMax = lo + ((lastTrainBin + 1) / n) * (hi - lo);
  // share of training calls in bins entirely below the lowest HIGH call (a lower bound, at bin resolution)
  const below = (v: number) => {
    const bin = Math.floor(((v - lo) / (hi - lo)) * n);
    return ident.train_score_hist.slice(0, Math.max(0, bin)).reduce((a, b) => a + b, 0) / ident.train_events;
  };
  const incidents = snapshot.incidents.filter((i) => i.identity === ident.name);

  let notice: string;
  if (flagged === 0) notice = `None of its ${num(ident.test_events)} calls this week crossed the threshold.`;
  else if (high.length && Math.min(...high) >= trainMax)
    notice = `${plural(high.length, "HIGH call")} this week scored above every one of its ${num(ident.train_events)} training calls.`;
  else if (high.length)
    notice = `${plural(flagged, "call")} crossed the threshold this week. The ${plural(high.length, "HIGH call")} scored higher than ${pct(below(Math.min(...high)), 1)} of its training calls.`;
  else
    notice = `${plural(flagged, "call")} out of ${num(ident.test_events)} this week crossed the threshold (${pct(flagged / ident.test_events)}), none of them HIGH.`;

  return (
    <section id={ident.name} className={`panel ${s.card}`} aria-labelledby={`h-${ident.name}`}>
      <header className={s.cardHead}>
        <div>
          <h2 id={`h-${ident.name}`} className="mono">
            {ident.name}
          </h2>
          <p className="faint">
            {num(ident.train_events)} training calls · {ident.own_forest ? "own model" : "global model"} · threshold{" "}
            <span className="num">{ident.threshold.toFixed(3)}</span>
          </p>
        </div>
        {incidents.length > 0 && (
          <ul className={s.incs}>
            {incidents.map((inc) => (
              <li key={inc.id}>
                <Link href={`/incidents/${inc.id}/`} aria-label={`${inc.severity} incident from ${inc.ip}`}>
                  <Sev level={inc.severity} />
                  <span className="mono faint">{inc.ip}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </header>

      <div className={s.body}>
        <div className={s.dist}>
          <h3 className={s.label}>Score distribution</h3>
          <ScoreDistribution ident={ident} index={index} />
          <p className="caption">
            <strong>What to notice:</strong> {notice}
          </p>
        </div>

        <div className={s.normal}>
          <h3 className={s.label}>Normal behaviour</h3>
          <div className={s.normalGrid}>
            <div>
              <h4 className={s.sub}>Active hours (UTC)</h4>
              <Hours hours={ident.hours} />
            </div>
            <Counts title="Top APIs" rows={ident.apis.slice(0, 5)} total={ident.train_events} />
            <Counts title="Source IPs" rows={ident.ips.slice(0, 4)} total={ident.train_events} />
            <div>
              <Counts title="Regions" rows={ident.regions} total={ident.train_events} />
              <h4 className={s.sub} style={{ marginTop: 12 }}>
                User agent
              </h4>
              <p className={`mono ${s.ua}`}>{ident.uas[0]?.[0]}</p>
              {ident.uas.length > 1 && <p className="faint" style={{ fontSize: 12 }}>+{ident.uas.length - 1} more</p>}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Counts({ title, rows, total }: { title: string; rows: [string, number][]; total: number }) {
  return (
    <div>
      <h4 className={s.sub}>{title}</h4>
      <ul className={s.counts}>
        {rows.map(([k, v]) => (
          <li key={k}>
            <span className={`mono ${s.key}`} title={k}>
              {k}
            </span>
            <span className="num faint">{pct(v / total, 0)}</span>
            <span className={s.track} aria-hidden="true">
              <span style={{ width: `${(v / total) * 100}%` }} />
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Hours({ hours }: { hours: number[] }) {
  const max = Math.max(...hours, 1);
  return (
    <div className={s.hours}>
      <div className={s.hourBars} role="img" aria-label={`Calls per hour; busiest hour ${hours.indexOf(max)}:00 UTC`}>
        {hours.map((h, i) => (
          <span key={i} style={{ height: `${h ? Math.max((h / max) * 100, 3) : 0}%` }} title={`${String(i).padStart(2, "0")}:00  ${num(h)} calls`} />
        ))}
      </div>
      <div className={s.hourAxis} aria-hidden="true">
        <span>00</span>
        <span>06</span>
        <span>12</span>
        <span>18</span>
        <span>24</span>
      </div>
    </div>
  );
}
