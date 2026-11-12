import type { Metadata } from "next";
import Link from "next/link";
import { Sev } from "@/components/Badges";
import { snapshot, topIncident } from "@/lib/data";
import { FEATURE_LABEL } from "@/lib/format";
import s from "./how.module.css";

export const metadata: Metadata = { title: "How it works" };

// Facts below are from infra/main.tf, tripwire/handler.py and tripwire/incidents.py.
const STAGES = [
  {
    name: "CloudTrail",
    role: "Records every AWS API call",
    detail: "Multi-region trail, read and write management events. Terraform can create one if the account has none.",
  },
  {
    name: "EventBridge",
    role: "Forwards each record",
    detail: "One rule, one Lambda invocation per call. The detector's own role is excluded so it never scores itself.",
  },
  {
    name: "Lambda",
    role: "Scores the call",
    detail: "Python 3.12. Computes the 7 features, walks the identity's Isolation Forest in plain Python, compares to its threshold.",
  },
  {
    name: "DynamoDB + S3",
    role: "Holds state",
    detail: "S3: one forest per identity, versioned. DynamoDB: baselines, a 10 minute window of recent calls, and open incidents.",
  },
  {
    name: "Bedrock",
    role: "Writes the summary (optional)",
    detail: "Gets only the extracted facts and writes 2 to 3 sentences. If it fails, the alert goes out with the raw facts.",
  },
  {
    name: "Slack",
    role: "Alerts on-call",
    detail: "One message per incident. Later calls edit it in place rather than posting again.",
  },
];

const SEVERE = ["T1098.001", "T1098.003", "T1562.008", "T1555.006", "T1578.002"];

export default function HowItWorks() {
  const inc = topIncident;
  const ex = inc.events.reduce((a, b) => (b.score > a.score ? b : a));
  const exIndex = inc.events.indexOf(ex);
  const severeHit = inc.techniques.filter((t) => SEVERE.includes(t.id));
  const ident = snapshot.identities.find((i) => i.name === inc.identity);
  const unusual = snapshot.run.features.filter((_, k) => {
    const p99 = ident?.feature_typical?.[k]?.[1];
    return p99 !== undefined && ex.features[k] > p99 + 1e-6;
  });

  return (
    <>
      <div className="page-head">
        <h1>How it works</h1>
        <p>
          A stolen key looks like its owner on paper: same account, same permissions. What changes is behaviour. Tripwire
          learns each identity&rsquo;s own normal from one week of CloudTrail, then scores every new call against it in
          real time. The whole stack deploys with one <code>terraform apply</code>.
        </p>
      </div>

      <section aria-labelledby="pipeline">
        <h2 id="pipeline" className="sr-only">
          Pipeline
        </h2>
        <ol className={s.flow}>
          {STAGES.map((st, i) => (
            <li key={st.name} className={s.stage}>
              <div className={s.box}>
                <span className={s.step}>{i + 1}</span>
                <h3>{st.name}</h3>
                <p className={s.role}>{st.role}</p>
                <p className={s.detail}>{st.detail}</p>
              </div>
              {i < STAGES.length - 1 && (
                <span className={s.arrow} aria-hidden="true">
                  <svg viewBox="0 0 24 12" width="24" height="12">
                    <path d="M0 6h20M15 1.5 20.5 6 15 10.5" fill="none" stroke="currentColor" strokeWidth="1.4" />
                  </svg>
                </span>
              )}
            </li>
          ))}
        </ol>
        <p className="caption">
          <strong>What to notice:</strong> nothing on this path retrains the model. Baselines only change when{" "}
          <code>scripts/train.py</code> runs, so an attacker who goes unnoticed can&rsquo;t teach it that they&rsquo;re
          normal.
        </p>
      </section>

      <section className="block" aria-labelledby="one-call">
        <div className="block-head">
          <h2 id="one-call">One call, start to finish</h2>
          <p>
            A real call from this week&rsquo;s top incident:{" "}
            <Link href={`/incidents/${inc.id}/`}>
              call {exIndex + 1} of {inc.events.length}
            </Link>
            .
          </p>
        </div>
        <ol className={`panel ${s.walk}`}>
          <li>
            <span className={s.n}>1</span>
            <div>
              <h3>A call arrives</h3>
              <p>
                <span className="mono">{inc.identity}</span> calls <span className="mono">{ex.api}</span> in{" "}
                <span className="mono">{ex.region}</span> from <span className="mono">{inc.ip}</span>
                {ex.error && ", and gets AccessDenied"}.
              </p>
            </div>
          </li>
          <li>
            <span className={s.n}>2</span>
            <div>
              <h3>Seven features, all against this identity&rsquo;s own history</h3>
              <p>
                {unusual.length
                  ? `Out of its normal range: ${unusual.map((f) => FEATURE_LABEL[f]).join(", ")}.`
                  : "No single feature is out of range."}{" "}
                The other features are within what <span className="mono">{inc.identity}</span> normally does.
              </p>
            </div>
          </li>
          <li>
            <span className={s.n}>3</span>
            <div>
              <h3>Score against its own threshold</h3>
              <p>
                Its forest scores the call <span className="mono num">{ex.score.toFixed(3)}</span>. The threshold for{" "}
                <span className="mono">{inc.identity}</span> is <span className="mono num">{ex.threshold.toFixed(3)}</span>,
                the 99.7th percentile of its training scores. Over the line, so it&rsquo;s flagged.
              </p>
            </div>
          </li>
          <li>
            <span className={s.n}>4</span>
            <div>
              <h3>Group into an incident</h3>
              <p>
                Flagged calls with the same identity and source IP join one incident (
                <span className="mono">{inc.key}</span>) until 30 minutes pass with nothing new. This one collected{" "}
                {inc.events.length} calls.
              </p>
            </div>
          </li>
          <li>
            <span className={s.n}>5</span>
            <div>
              <h3>Map to ATT&amp;CK and set severity</h3>
              <p>
                {ex.technique ? (
                  <>
                    <span className="mono">{ex.api}</span> maps to <span className="mono">{ex.technique[0]}</span>{" "}
                    {ex.technique[1]}.{" "}
                  </>
                ) : null}
                An incident is <Sev level="HIGH" /> if it touches credentials, permissions, compute or logging (
                {SEVERE.join(", ")}), or has 5+ calls from a new IP.{" "}
                {severeHit.length > 0 && `This one hit ${severeHit.length} of those techniques.`}
              </p>
            </div>
          </li>
          <li>
            <span className={s.n}>6</span>
            <div>
              <h3>Alert once, then update</h3>
              <p>
                The first flagged call posts to Slack. Each later call edits the same message, and Bedrock rewrites the
                summary only when the severity changes. The message ends with one instruction: <strong>{inc.action}</strong>
              </p>
            </div>
          </li>
        </ol>
      </section>

      <section className="block" aria-labelledby="repro">
        <div className="block-head">
          <h2 id="repro">Reproducible and tested</h2>
        </div>
        <div className={s.repro}>
          <div>
            <h3>Infrastructure as code</h3>
            <p>
              Every resource is in <code>infra/</code>: the Lambda, the EventBridge rule, three DynamoDB tables, the
              versioned model bucket, the Slack secret, and an IAM policy scoped to each table and bucket. One <code>terraform apply</code> builds it.
            </p>
          </div>
          <div>
            <h3>Red team in CI</h3>
            <p>
              A manual GitHub Actions workflow runs four Stratus Red Team techniques against the deployed stack: discovery,
              secrets retrieval, admin user creation and CloudTrail stop. It fails unless a HIGH incident appears within
              10 minutes.
            </p>
          </div>
          <div>
            <h3>Small enough for Lambda</h3>
            <p>
              Trained with scikit-learn, scored without it. The trees are exported to JSON and walked in plain Python. A
              test checks the result matches scikit-learn to 1e-12.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
