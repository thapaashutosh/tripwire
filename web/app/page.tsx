import Link from "next/link";
import { Sev, Truth } from "@/components/Badges";
import { WeekTimeline } from "@/components/WeekTimeline";
import { snapshot, topIncident, totals } from "@/lib/data";
import { duration, headline, num, pct, plural, weekTime } from "@/lib/format";
import s from "./overview.module.css";

export default function Overview() {
  const top = topIncident;
  const denied = top.events.filter((e) => e.error).length;
  const lastTech = top.techniques[top.techniques.length - 1];

  const tells: { label: string; value: string; plain?: boolean }[] = [];
  if (top.new_ip) tells.push({ label: "First call ever from", value: top.ip });
  if (top.new_ua) tells.push({ label: "Never-seen user agent", value: top.events[0].ua });
  if (top.new_regions.length) tells.push({ label: "New region", value: top.new_regions.join(", ") });
  if (denied) tells.push({ label: "AccessDenied on", value: `${denied} of ${top.events.length} calls`, plain: true });
  if (lastTech) tells.push({ label: "Last call", value: `${lastTech.api} (${lastTech.id})` });

  const stats = [
    { k: "Calls scored", v: num(totals.scored), sub: "one week, 5 identities" },
    { k: "Flagged", v: num(totals.flagged), sub: `${pct(totals.flagged / totals.scored)} of all calls` },
    {
      k: "Incidents",
      v: num(totals.incidents),
      sub: `${totals.bySeverity.HIGH} HIGH · ${totals.bySeverity.MEDIUM} MEDIUM · ${totals.bySeverity.LOW} LOW`,
    },
    { k: "Attack calls caught", v: `${totals.caught} / ${totals.attackCalls}`, sub: "checked against simulator truth" },
    {
      k: "False positives",
      v: num(totals.falsePositives),
      sub: `${pct(totals.falsePositives / totals.normalCalls)} of ${num(totals.normalCalls)} normal calls`,
    },
  ];

  return (
    <>
      <section className={s.hero} aria-labelledby="headline">
        <p className={s.kicker}>
          <Sev level={top.severity} />
          <span>Top incident this week · {weekTime(top.events[0].t)} UTC</span>
        </p>
        <h1 id="headline" className={s.headline}>
          {headline(top)}.
        </h1>
        <p className={s.sub}>
          Tripwire gives every AWS identity its own anomaly model, so &ldquo;unusual&rdquo; means unusual for that key.
          These {top.events.length} calls didn&rsquo;t look like anything <span className="mono">{top.identity}</span>{" "}
          had done before, so they became one incident with one Slack alert and one instruction:{" "}
          <strong>{top.action}</strong>
        </p>
        <div className={s.ctaRow}>
          <Link href={`/incidents/${top.id}/`} className={s.cta}>
            Replay the attack, call by call
            <span aria-hidden="true"> →</span>
          </Link>
          <Link href="/how-it-works/" className={s.ctaQuiet}>
            How it works
          </Link>
        </div>
        <ul className={s.tells} aria-label="What gave it away">
          {tells.map((t) => (
            <li key={t.label} className="chip">
              {t.label} <b className={t.plain ? undefined : "mono"}>{t.value}</b>
            </li>
          ))}
        </ul>
      </section>

      <dl className={s.stats}>
        {stats.map((x) => (
          <div key={x.k}>
            <dt>{x.k}</dt>
            <dd className="num">{x.v}</dd>
            <dd className={s.statSub}>{x.sub}</dd>
          </div>
        ))}
      </dl>

      <section className="block" aria-labelledby="week">
        <div className="block-head">
          <h2 id="week">The week, call by call</h2>
          <p>Each dot is one API call. Height is its score minus its own identity&rsquo;s threshold.</p>
        </div>
        <div className="panel">
          <WeekTimeline />
        </div>
        <p className="caption">
          <strong>What to notice:</strong> {num(totals.scored - totals.flagged)} normal calls stay below the line all
          week. On {weekTime(top.events[0].t)}, {top.events.length} calls from{" "}
          <span className="mono">{top.identity}</span> jump above it within {duration(top.events[top.events.length - 1].t - top.events[0].t)}.{" "}
          <span className="faint">The area above the line is drawn taller than the area below so flagged calls don&rsquo;t overlap.</span>
        </p>
      </section>

      <section className="block" aria-labelledby="incidents">
        <div className="block-head">
          <h2 id="incidents">All {totals.incidents} incidents</h2>
          <p>
            Flagged calls are grouped by identity and source IP. {plural(totals.falseIncidents, "incident")} came from
            normal traffic, the false positives.
          </p>
        </div>
        <ul className={`panel ${s.list}`}>
          {snapshot.incidents.map((inc) => (
            <li key={inc.id}>
              <Link href={`/incidents/${inc.id}/`}>
                <span className={s.listTop}>
                  <Sev level={inc.severity} />
                  <span className="faint num">{weekTime(inc.events[0].t)}</span>
                </span>
                <span className="mono">
                  {inc.identity} <span className="faint">from</span> {inc.ip}
                </span>
                <span className={s.listMeta}>
                  {plural(inc.events.length, "call")}
                  {inc.new_ip && " · new IP"} · <Truth attack={inc.attack} />
                </span>
              </Link>
            </li>
          ))}
        </ul>
        <div className={`panel table-wrap ${s.table}`}>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Identity</th>
                <th>Source IP</th>
                <th className="r">Calls</th>
                <th>Started (UTC)</th>
                <th className="r">ATT&amp;CK</th>
                <th>Ground truth</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.incidents.map((inc) => (
                <tr key={inc.id} className="linked">
                  <td>
                    <Link href={`/incidents/${inc.id}/`} className="row-link" aria-label={`Open incident: ${inc.severity}, ${inc.identity} from ${inc.ip}`}>
                      <Sev level={inc.severity} />
                    </Link>
                  </td>
                  <td className="mono">{inc.identity}</td>
                  <td className="mono">
                    {inc.ip}
                    {inc.new_ip && <span className={s.newTag}>new</span>}
                  </td>
                  <td className="r num">{inc.events.length}</td>
                  <td className="num">{weekTime(inc.events[0].t)}</td>
                  <td className="r num">{inc.techniques.length || <span className="faint">–</span>}</td>
                  <td>
                    <Truth attack={inc.attack} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="caption">
          Ground truth comes from the simulator and is never shown to the detector. It&rsquo;s here so you can check the
          detector&rsquo;s work.
        </p>
      </section>
    </>
  );
}
