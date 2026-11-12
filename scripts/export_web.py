"""Write the data the web dashboard reads.

    python -m scripts.export_web --seed 3

Runs the same pipeline as scripts/evaluate.py for one seed (train on week 1, score week 2 with the
stolen key attack injected) and writes web/data/snapshot.json. Nothing in the dashboard is made up:
every score, threshold and incident comes from this run.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

from tripwire.features import FEATURES, Timeline, featurize, featurize_history
from tripwire.incidents import MITRE, action, facts, group, slack_text
from tripwire.model import GLOBAL, Detector, train
from tripwire.simulate import generate_week, stolen_key_attack

WEEK = 7 * 1440


def top(counter, n=8):
    return [[k, v] for k, v in counter.most_common(n)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=3)
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument("--fp-budget", type=float, default=0.003)
    ap.add_argument("--out", default="web/data/snapshot.json")
    ap.add_argument("--eval", default="results/eval.json")
    a = ap.parse_args()

    history = generate_week(a.seed)
    stats, X = featurize_history(history)
    models = train(X, n_trees=a.trees, fp_budget=a.fp_budget, seed=a.seed)
    det = Detector(models)

    normal = generate_week(a.seed + 1000, start=WEEK)
    attack_start = WEEK + 4 * 1440 + 3 * 60 + 12
    attack = stolen_key_attack(start=attack_start)
    test = sorted(normal + attack, key=lambda e: e.t)

    by_id = defaultdict(list)
    for e in test:
        by_id[e.identity].append(e)

    scored = {}  # id(event) -> (score, threshold, features)
    flagged = []
    for ident, evs in by_id.items():
        tl = Timeline(evs)
        s = stats.get(ident)
        f = det.forest_for(ident)
        for e in evs:
            x = featurize(e, s, tl) if s else [10.0] * 7
            sc = f.score(x)
            scored[id(e)] = (sc, f.threshold, x)
            if sc > f.threshold:
                flagged.append(e)

    incidents = group(flagged, stats)
    inc_of = {}
    inc_out = []
    for n, inc in enumerate(incidents):
        for e in inc.events:
            inc_of[id(e)] = n
        evs = []
        for e in inc.events:
            sc, th, x = scored[id(e)]
            m = MITRE.get(e.api)
            evs.append({
                "t": round(e.t - WEEK, 3), "api": e.api, "region": e.region, "ua": e.ua, "error": e.error,
                "key_id": e.key_id, "score": round(sc, 4), "threshold": round(th, 4),
                "features": [round(v, 3) + 0.0 for v in x], "attack": e.attack,
                "technique": list(m) if m else None,
            })
        inc_out.append({
            "id": n, "key": inc.key, "identity": inc.identity, "ip": inc.ip, "severity": inc.severity,
            "new_ip": inc.new_ip, "new_regions": inc.new_regions, "new_ua": inc.new_ua,
            "techniques": [{"id": t, "api": api, "denied": err, "name": MITRE[api][1]} for t, api, err in inc.techniques],
            "key_ids": inc.key_ids, "facts": facts(inc), "action": action(inc),
            "slack_text": slack_text(inc, None), "attack": any(e.attack for e in inc.events), "events": evs,
        })

    ident_names = sorted(by_id)
    idx = {n: i for i, n in enumerate(ident_names)}

    # training scores, i.e. the distribution each threshold was cut from
    train_scores = {name: [det.forest_for(name).score(x) for x in X.get(name, [])] for name in ident_names}
    all_scores = [s for v in train_scores.values() for s in v] + [scored[id(e)][0] for e in test]
    lo, hi = math.floor(min(all_scores) * 50) / 50, math.ceil(max(all_scores) * 50) / 50
    bins = 50

    def hist(values):
        counts = [0] * bins
        for v in values:
            counts[min(bins - 1, int((v - lo) / (hi - lo) * bins))] += 1
        return counts

    def typical(name):
        """Median and 99th percentile of each feature over the identity's training calls."""
        rows = X.get(name, [])
        if not rows:
            return None
        out = []
        for k in range(len(FEATURES)):
            col = sorted(r[k] for r in rows)
            out.append([round(statistics.median(col), 3) + 0.0, round(col[min(len(col) - 1, int(0.99 * len(col)))], 3) + 0.0])
        return out

    identities = []
    for name in ident_names:
        s = stats.get(name)
        own = name in models
        identities.append({
            "train_score_hist": hist(train_scores[name]),
            "test_score_hist": hist([scored[id(e)][0] for e in by_id[name]]),
            "feature_typical": typical(name),
            "name": name, "own_forest": own,
            "threshold": round(det.forest_for(name).threshold, 4),
            "train_events": s.n if s else 0,
            "test_events": len(by_id[name]),
            "apis": top(s.api) if s else [], "ips": top(s.ip, 6) if s else [],
            "regions": top(s.region, 4) if s else [], "uas": top(s.ua, 3) if s else [],
            "hours": s.hour if s else [0] * 24,
        })

    # compact: [minutes into week 2, identity index, score, incident index or -1, attack 0/1]
    points = [[round(e.t - WEEK, 2), idx[e.identity], round(scored[id(e)][0], 4), inc_of.get(id(e), -1), int(e.attack)]
              for e in test]

    caught = sum(e.attack for e in flagged)
    fp = sum(not e.attack for e in flagged)
    out = {
        "run": {
            "seed": a.seed, "trees": a.trees, "fp_budget": a.fp_budget, "features": FEATURES,
            "normal_events": len(normal), "attack_events": len(attack), "caught": caught,
            "false_positives": fp, "attack_start": attack_start - WEEK, "global_threshold": round(models[GLOBAL]["threshold"], 4),
            "score_bins": {"lo": lo, "hi": hi, "n": bins},
        },
        "identities": identities,
        "incidents": inc_out,
        "points": points,
        "eval": json.loads(Path(a.eval).read_text()) if Path(a.eval).exists() else None,
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, separators=(",", ":")))
    print(f"wrote {a.out}: {len(incidents)} incidents, caught {caught}/{len(attack)}, {fp} false positives")


if __name__ == "__main__":
    main()
