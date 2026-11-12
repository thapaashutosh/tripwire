import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Sev, Truth } from "@/components/Badges";
import { IncidentTimeline } from "@/components/IncidentTimeline";
import { SlackMessage } from "@/components/SlackMessage";
import { getIdentity, getIncident, snapshot } from "@/lib/data";
import { duration, plural, span, weekTime } from "@/lib/format";
import s from "./incident.module.css";

export const dynamicParams = false;

export function generateStaticParams() {
  return snapshot.incidents.map((i) => ({ id: String(i.id) }));
}

export async function generateMetadata({ params }: PageProps<"/incidents/[id]">): Promise<Metadata> {
  const inc = getIncident(Number((await params).id));
  return { title: inc ? `${inc.severity}: ${inc.identity} from ${inc.ip}` : "Incident" };
}

export default async function IncidentPage({ params }: PageProps<"/incidents/[id]">) {
  const inc = getIncident(Number((await params).id));
  if (!inc) notFound();
  const ident = getIdentity(inc.identity);
  const denied = inc.events.filter((e) => e.error).length;
  const others = snapshot.incidents.filter((i) => i.id !== inc.id);
  const high = inc.severity === "HIGH";

  const changes: { label: string; value: string }[] = [];
  if (inc.new_ip) changes.push({ label: "Source IP never used by this identity", value: inc.ip });
  if (inc.new_ua) changes.push({ label: "User agent never used by this identity", value: inc.events[0].ua });
  if (inc.new_regions.length) changes.push({ label: "Region never used by this identity", value: inc.new_regions.join(", ") });

  return (
    <>
      <nav className={s.crumb} aria-label="Breadcrumb">
        <Link href="/">Overview</Link>
        <span aria-hidden="true">/</span>
        <span className="mono">{inc.key}</span>
      </nav>

      <header className={s.head}>
        <div className={s.titleRow}>
          <Sev level={inc.severity} />
          <Truth attack={inc.attack} />
        </div>
        <h1 className={s.title}>
          <span className="mono">{inc.identity}</span> <span className={s.from}>from</span>{" "}
          <span className="mono">{inc.ip}</span>
        </h1>
        <p className={s.lede}>
          {inc.events.length === 1
            ? `One flagged call at ${weekTime(inc.events[0].t, true)} UTC.`
            : `${inc.events.length} flagged calls in ${duration(span(inc))}, starting ${weekTime(inc.events[0].t, true)} UTC.`}
          {denied > 0 && ` ${plural(denied, "call")} returned AccessDenied.`}
          {inc.techniques.length > 0 && ` Mapped to ${plural(inc.techniques.length, "MITRE ATT&CK technique")}.`}
          {!inc.attack && " This came from normal simulated traffic, so it is a false positive."}
        </p>
      </header>

      <section className={s.action} aria-labelledby="do-this">
        <h2 id="do-this">Do this</h2>
        <p>{inc.action}</p>
      </section>

      <section className="block" aria-labelledby="calls">
        <div className="block-head">
          <h2 id="calls">What the {inc.attack ? "attacker" : "caller"} did</h2>
          <p>Select a call to see which of the 7 features made it stand out.</p>
        </div>
        <IncidentTimeline
          inc={inc}
          features={snapshot.run.features}
          typical={ident?.feature_typical ?? null}
          trainN={ident?.train_events ?? 1}
        />
        <p className="caption">
          <strong>What to notice:</strong> the {high ? "red" : "grey"} bar is each call&rsquo;s anomaly score and the
          white tick is its identity&rsquo;s threshold. A feature counts as unusual when it is higher than 99% of this
          identity&rsquo;s own training calls.
        </p>
      </section>

      <div className={`block ${s.lower}`}>
        <section aria-labelledby="slack">
          <div className="block-head">
            <h2 id="slack">Slack alert</h2>
            <p>Exactly as the pipeline formats it.</p>
          </div>
          <SlackMessage text={inc.slack_text} />
          <p className={s.note}>
            Bedrock wasn&rsquo;t called in this export, so this is the fallback the Lambda sends when the model is off or
            fails: raw facts, no summary. Later calls in the same incident edit this message instead of posting a new
            one.
          </p>
        </section>

        <div className={s.facts}>
          {changes.length > 0 && (
            <section aria-labelledby="new">
              <h2 id="new" className={s.factHead}>
                New for <span className="mono">{inc.identity}</span>
              </h2>
              <dl className={s.changes}>
                {changes.map((c) => (
                  <div key={c.label}>
                    <dt>{c.label}</dt>
                    <dd className="mono">{c.value}</dd>
                  </div>
                ))}
              </dl>
            </section>
          )}

          {inc.techniques.length > 0 && (
            <section aria-labelledby="attack">
              <h2 id="attack" className={s.factHead}>
                MITRE ATT&amp;CK
              </h2>
              <ul className={s.techs}>
                {inc.techniques.map((t) => (
                  <li key={t.api}>
                    <a
                      href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                      target="_blank"
                      rel="noreferrer"
                      className="mono"
                    >
                      {t.id}
                      <span className="sr-only"> (opens attack.mitre.org)</span>
                    </a>
                    <span>{t.name}</span>
                    <span className="faint">
                      via <span className="mono">{t.api}</span>
                      {t.denied && " · denied"}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      </div>

      <section className="block" aria-labelledby="other">
        <div className="block-head">
          <h2 id="other">Other incidents this week</h2>
        </div>
        <ul className={s.others}>
          {others.map((o) => (
            <li key={o.id}>
              <Link href={`/incidents/${o.id}/`}>
                <Sev level={o.severity} />
                <span className="mono">{o.identity}</span>
                <span className="mono faint">{o.ip}</span>
                <span className="faint num">{plural(o.events.length, "call")}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}
