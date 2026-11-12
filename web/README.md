# tripwire web

Dashboard for the detector: incidents, the per-call evidence behind each one, every identity's score over the week, and the evaluation numbers. Next.js 16 (App Router, TypeScript), exported as a static site.

## Where the data comes from

The Lambda has no HTTP API, so the dashboard reads `data/snapshot.json`, which `scripts/export_web.py` writes. That script runs the same pipeline as `scripts/evaluate.py` for one seed: train on week 1, score week 2 with the stolen key attack injected, group flagged calls into incidents. Every score, threshold, incident and Slack message in the UI is real output from that run. Nothing is hand-written.

```bash
# from the repo root, with the Python venv active
python -m scripts.export_web --seed 3     # or: npm run data (from web/)
```

Bedrock isn't called during export, so incident pages show the fallback message the Lambda sends when no model is configured.

## Run it

```bash
cd web
npm install
npm run dev          # http://localhost:3000
npm run build        # static site in web/out/, can be served from S3
```

## Layout

```
app/page.tsx                  overview: headline, stats, the week on one axis, all incidents
app/incidents/[id]/page.tsx   one incident: step timeline with replay, 7-feature breakdown, Slack text, ATT&CK
app/identities/page.tsx       each identity's training score distribution vs threshold, and its normal behaviour
app/evaluation/page.tsx       results/eval.json across seeds, labelled as synthetic
app/how-it-works/page.tsx     pipeline diagram and one real call walked through it
components/WeekTimeline.tsx   every call as score minus its identity's threshold, server-rendered SVG
components/IncidentTimeline.tsx  client component: step selection and the replay
lib/data.ts                   snapshot types (keep in sync with scripts/export_web.py)
lib/format.ts                 inverts the feature formulas back into plain facts
```

Per identity, the export also writes `train_score_hist` (the distribution its threshold was cut from) and
`feature_typical` (median and 99th percentile of each feature over its training calls). A call's feature is shown
as unusual when it is above that 99th percentile.

On each call, "never seen in training" and "9 calls in the last 10 min" come from inverting the formulas in
`tripwire/features.py`. If the formulas change, update `featureFact` too.

Design rules: dark only; the one accent colour means HIGH severity and nothing else; severity is always icon plus
word; every chart has a "What to notice" caption.
