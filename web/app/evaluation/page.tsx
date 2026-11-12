import type { Metadata } from "next";
import { Sev } from "@/components/Badges";
import { snapshot } from "@/lib/data";
import { num, pct } from "@/lib/format";
import s from "./evaluation.module.css";

export const metadata: Metadata = { title: "Evaluation" };

export default function EvaluationPage() {
  const ev = snapshot.eval;
  const shown = snapshot.run.seed;
  const missedRuns = ev ? ev.runs.filter((r) => r.caught < r.attack_events).length : 0;
  const fpHigh = snapshot.incidents.filter((i) => !i.attack && i.severity === "HIGH");
  const fpHighIds = [...new Set(fpHigh.map((i) => i.identity))];

  return (
    <>
      <div className="page-head">
        <h1>Evaluation</h1>
        <p>
          Five independent runs. Each one trains on a week of synthetic traffic, then scores a different week with a 9
          call stolen key attack injected. Thresholds are set from the training week only, so the detector never sees
          the attack before it is tested on it.
        </p>
      </div>

      <div className={s.notice} role="note">
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
          <circle cx="8" cy="8" r="6.6" fill="none" stroke="currentColor" strokeWidth="1.4" />
          <path d="M8 7.2v4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          <circle cx="8" cy="4.9" r="0.9" fill="currentColor" />
        </svg>
        <p>
          <strong>Synthetic traffic.</strong> Five simulated identities, 5,000 normal calls per week, documentation IP
          ranges and AWS example keys. Real accounts are noisier, so treat these numbers as a check that the method
          works, not as a production false positive rate.
        </p>
      </div>

      {ev ? (
        <section className="block" aria-labelledby="results">
          <div className="block-head">
            <h2 id="results">Results by seed</h2>
            <p>
              Reproduce with <code>python -m scripts.evaluate --seeds 5</code>. CI runs it on every push.
            </p>
          </div>

          <dl className={s.summary}>
            <div>
              <dt>Attack caught as</dt>
              <dd>one HIGH incident in {ev.runs.filter((r) => r.attack_incidents === 1 && r.attack_severity === "HIGH").length} of {ev.runs.length} runs</dd>
            </div>
            <div>
              <dt>Attack calls caught, worst run</dt>
              <dd className="num">{Math.round(ev.summary.recall_min * 9)} of 9</dd>
            </div>
            <div>
              <dt>False positive rate</dt>
              <dd className="num">
                {pct(ev.summary.fp_rate_mean)} mean, {pct(ev.summary.fp_rate_max)} worst
              </dd>
            </div>
          </dl>

          <div className="panel table-wrap">
            <table>
              <caption className="sr-only">Per-seed evaluation results on synthetic traffic</caption>
              <thead>
                <tr>
                  <th>Seed</th>
                  <th className="r">Attack calls caught</th>
                  <th className="r">False positives</th>
                  <th className="r">FP rate</th>
                  <th className="r">Incidents raised</th>
                  <th>Attack became</th>
                  <th className="r">Scoring time</th>
                </tr>
              </thead>
              <tbody>
                {ev.runs.map((r) => (
                  <tr key={r.seed} className={r.seed === shown ? s.shown : undefined}>
                    <td className="num">
                      {r.seed}
                      {r.seed === shown && <span className={s.shownTag}>shown on other pages</span>}
                    </td>
                    <td className="r num">
                      {r.caught} / {r.attack_events}
                    </td>
                    <td className="r num">
                      {r.false_positives} / {num(r.normal_events)}
                    </td>
                    <td className="r num">{pct(r.fp_rate)}</td>
                    <td className="r num">{r.incidents}</td>
                    <td>
                      <span className={s.became}>
                        {r.attack_incidents} × {r.attack_severity ? <Sev level={r.attack_severity} /> : "missed"}
                      </span>
                    </td>
                    <td className="r num">{r.score_ms_per_event.toFixed(2)} ms/call</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="caption">
            <strong>What to notice:</strong>{" "}
            {missedRuns === 0
              ? "every run caught all attack calls."
              : `${missedRuns} of ${ev.runs.length} runs missed one attack call.`}{" "}
            The one missed is usually the first, <span className="mono">GetCallerIdentity</span>, which comes before the
            burst features have anything to count. The attack still became a HIGH incident every time.
          </p>
        </section>
      ) : (
        <p className="muted">
          No <code>results/eval.json</code> was found when the snapshot was exported.
        </p>
      )}

      <section className="block" aria-labelledby="limits">
        <div className="block-head">
          <h2 id="limits">What these numbers don&rsquo;t show</h2>
        </div>
        <ul className={s.limits}>
          <li>
            <strong>Real traffic.</strong> The next step is replaying a public CloudTrail dataset and reporting those
            numbers separately.
          </li>
          <li>
            <strong>Every region.</strong> CloudTrail events reach EventBridge in the region where the call was made, and
            IAM and STS events land in us-east-1. Covering several regions means deploying the rule in each one.
          </li>
          <li>
            <strong>Read-only recon.</strong> Most attacker recon is <span className="mono">List*</span>,{" "}
            <span className="mono">Describe*</span>, <span className="mono">Get*</span>. Check those events actually
            reach EventBridge in your account.
          </li>
          <li>
            <strong>A careful attacker.</strong> Someone who copies the victim&rsquo;s user agent and works from inside
            its usual IP range looks a lot more normal. Tripwire is one layer, not the whole defence.
          </li>
          {fpHigh.length > 0 && (
            <li>
              <strong>Noisy identities.</strong> In the run shown here, normal traffic from{" "}
              {fpHighIds.map((id, k) => (
                <span key={id}>
                  {k > 0 && ", "}
                  <span className="mono">{id}</span>
                </span>
              ))}{" "}
              produced {fpHigh.length} HIGH incident{fpHigh.length > 1 ? "s" : ""}. In the simulator,{" "}
              <span className="mono">ci-deploy</span> rotates through 40 CI runner IPs, so &ldquo;new IP&rdquo; fires
              often.
            </li>
          )}
        </ul>
      </section>
    </>
  );
}
