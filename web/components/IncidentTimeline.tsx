"use client";

import { useEffect, useState } from "react";
import type { FeatureName, Incident } from "@/lib/data";
import { FEATURE_LABEL, offset, weekTime } from "@/lib/format";
import { Denied } from "./Badges";
import { FeatureBreakdown, featureRows } from "./FeatureBreakdown";
import s from "./IncidentTimeline.module.css";

const STEP_MS = 750;

// shared scale for score bars on this page
const BAR_LO = 0.45;
const BAR_HI = 0.85;
const barAt = (v: number) => `${(Math.min(Math.max((v - BAR_LO) / (BAR_HI - BAR_LO), 0), 1) * 100).toFixed(1)}%`;

interface Props {
  inc: Incident;
  features: FeatureName[];
  typical: [number, number][] | null;
  trainN: number;
}

export function IncidentTimeline({ inc, features, typical, trainN }: Props) {
  const calls = inc.events;
  const t0 = calls[0].t;
  const spanMin = Math.max(calls[calls.length - 1].t - t0, 1e-6);
  const [selected, setSelected] = useState(0);
  const [revealed, setRevealed] = useState(calls.length);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    if (!playing) return;
    const id = setTimeout(() => {
      const next = revealed + 1;
      setRevealed(next);
      setSelected(next - 1);
      if (next >= calls.length) setPlaying(false);
    }, revealed === 0 ? 150 : STEP_MS);
    return () => clearTimeout(id);
  }, [playing, revealed, calls.length]);

  const replay = () => {
    if (playing) {
      setPlaying(false);
      setRevealed(calls.length);
      return;
    }
    setRevealed(0);
    setSelected(0);
    setPlaying(true);
  };

  const rows = calls.map((c) => featureRows(c, features, typical));
  const cur = calls[selected];
  const curRows = rows[selected];

  const breakdown = (
    <div className={s.why}>
      <div className={s.whyHead}>
        <h3>
          Why call {selected + 1} of {calls.length} was flagged
        </h3>
        <p className="muted">
          <span className="mono">{cur.api}</span> scored <span className="mono num">{cur.score.toFixed(3)}</span>, over
          this identity&rsquo;s threshold of <span className="mono num">{cur.threshold.toFixed(3)}</span>. Each feature is
          compared with {trainN.toLocaleString("en-US")} training calls from{" "}
          <span className="mono">{inc.identity}</span>.
        </p>
      </div>
      <FeatureBreakdown rows={curRows} n={trainN} />
      <p className={s.legendLine}>
        <span className={s.key}>
          <span className={s.kBand} aria-hidden="true" /> normal range (to 99th percentile)
        </span>
        <span className={s.key}>
          <span className={s.kMedian} aria-hidden="true" /> median
        </span>
        <span className={s.key}>
          <span className={s.kValue} aria-hidden="true" /> this call
        </span>
      </p>
    </div>
  );

  return (
    <div className={`${s.wrap} ${inc.severity === "HIGH" ? s.isHigh : ""}`}>
      {calls.length > 1 && (
        <div className={`panel ${s.pace}`}>
          <button type="button" onClick={replay} className={s.play} aria-pressed={playing}>
            {playing ? (
              <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
                <rect x="2" y="2" width="8" height="8" rx="1" fill="currentColor" />
              </svg>
            ) : (
              <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
                <path d="M3 1.5v9l7.5-4.5z" fill="currentColor" />
              </svg>
            )}
            {playing ? "Stop" : "Replay attack"}
          </button>
          <div className={s.track}>
            <div className={s.axis} aria-hidden="true">
              {calls.map((c, i) => (
                <span
                  key={i}
                  className={`${s.tick} ${i < revealed ? s.on : ""} ${i === selected ? s.sel : ""} ${c.error ? s.err : ""}`}
                  style={{ left: `${((c.t - t0) / spanMin) * 100}%` }}
                />
              ))}
            </div>
            <div className={s.axisLabels}>
              <span className="num">{weekTime(t0, true)}</span>
              <span className="faint">
                {calls.length} calls over {offset(spanMin).slice(1)} min · ticks are calls at their real spacing, dashed
                ones were denied
              </span>
              <span className="num">{weekTime(calls[calls.length - 1].t, true)}</span>
            </div>
          </div>
          <p className="sr-only" aria-live="polite">
            {playing && revealed > 0
              ? `Call ${revealed} of ${calls.length}: ${calls[revealed - 1].api}${calls[revealed - 1].error ? ", AccessDenied" : ""}`
              : ""}
          </p>
        </div>
      )}

      <div className={s.grid}>
        <ol className={s.steps} aria-label="Calls in order">
          {calls.map((c, i) => {
            const unusual = rows[i].filter((r) => r.unusual).map((r) => FEATURE_LABEL[r.name]);
            const hidden = i >= revealed;
            return (
              <li key={i} className={`${s.step} ${hidden ? s.hidden : ""} ${i === selected ? s.active : ""}`}>
                <span className={s.rail} aria-hidden="true">
                  <span className={s.node}>{i + 1}</span>
                </span>
                <div className={s.body}>
                  <button
                    type="button"
                    className={s.stepBtn}
                    aria-pressed={i === selected}
                    aria-label={`Call ${i + 1}: ${c.api}${c.error ? ", AccessDenied" : ""}. Show why it was flagged`}
                    onClick={() => setSelected(i)}
                    disabled={hidden}
                  >
                    <span className={s.timeRow}>
                      <span className="mono num">{offset(c.t - t0)}</span>
                      <span className="faint num">{weekTime(c.t, true)}</span>
                    </span>
                    <span className={s.apiRow}>
                      <span className={`mono ${s.api}`}>{c.api}</span>
                      {c.error && <Denied />}
                      <span className={`mono faint ${s.region}`}>{c.region}</span>
                    </span>
                    {c.technique ? (
                      <span className={s.tech}>
                        <span className="mono">{c.technique[0]}</span> {c.technique[1]}
                      </span>
                    ) : (
                      <span className={`${s.tech} faint`}>No ATT&amp;CK mapping for this API</span>
                    )}
                    <span className={s.scoreRow}>
                      <span className={s.bar} aria-hidden="true">
                        <span className={s.fill} style={{ width: barAt(c.score) }} />
                        <span className={s.th} style={{ left: barAt(c.threshold) }} />
                      </span>
                      <span className="mono num">{c.score.toFixed(3)}</span>
                      <span className="faint num">
                        {c.score >= c.threshold ? "+" : ""}
                        {(c.score - c.threshold).toFixed(3)} vs threshold
                      </span>
                    </span>
                    <span className={s.unusualRow}>
                      {unusual.length ? (
                        <>
                          <span className="faint">Unusual:</span> {unusual.join(" · ")}
                        </>
                      ) : (
                        <span className="faint">No single feature beyond its normal range; the combination was unusual</span>
                      )}
                    </span>
                  </button>
                  {i === selected && <div className={s.inlineWhy}>{breakdown}</div>}
                </div>
              </li>
            );
          })}
        </ol>

        <aside className={`panel ${s.side}`} aria-label="Feature breakdown for the selected call">
          {breakdown}
        </aside>
      </div>
    </div>
  );
}
