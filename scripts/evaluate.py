"""Reproduce the headline numbers.

    python -m scripts.evaluate --seeds 5

Week 1: 5,000 normal events, used to build baselines, train one forest per identity, and set
each identity's threshold at its own 99.7th percentile. Week 2: a fresh 5,000 normal events
from a different seed plus a 9 call stolen key attack. Nothing about week 2 is used in training.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import defaultdict
from pathlib import Path

from tripwire.features import Timeline, featurize, featurize_history
from tripwire.incidents import group
from tripwire.model import Detector, train
from tripwire.simulate import generate_week, stolen_key_attack

WEEK = 7 * 1440


def run(seed: int, n_trees: int = 100, fp_budget: float = 0.003) -> dict:
    history = generate_week(seed)
    stats, X = featurize_history(history)
    t0 = time.perf_counter()
    det = Detector(train(X, n_trees=n_trees, fp_budget=fp_budget, seed=seed))
    train_s = time.perf_counter() - t0

    normal = generate_week(seed + 1000, start=WEEK)
    attack = stolen_key_attack(start=WEEK + 4 * 1440 + 3 * 60 + 12)  # friday 03:12 of week 2
    test = sorted(normal + attack, key=lambda e: e.t)

    by_id = defaultdict(list)
    for e in test:
        by_id[e.identity].append(e)
    flagged = []
    t0 = time.perf_counter()
    for ident, evs in by_id.items():
        tl = Timeline(evs)
        s = stats.get(ident)
        for e in evs:
            x = featurize(e, s, tl) if s else [10.0] * 7
            if det.is_anomalous(ident, x):
                flagged.append(e)
    score_ms = (time.perf_counter() - t0) * 1000 / len(test)

    caught = sum(e.attack for e in flagged)
    fp = sum(not e.attack for e in flagged)
    incidents = group(flagged, stats)
    atk_incidents = [i for i in incidents if any(e.attack for e in i.events)]
    return {
        "seed": seed,
        "normal_events": len(normal),
        "attack_events": len(attack),
        "caught": caught,
        "false_positives": fp,
        "fp_rate": fp / len(normal),
        "incidents": len(incidents),
        "attack_incidents": len(atk_incidents),
        "attack_severity": atk_incidents[0].severity if atk_incidents else None,
        "train_seconds": round(train_s, 2),
        "score_ms_per_event": round(score_ms, 3),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument("--fp-budget", type=float, default=0.003)
    ap.add_argument("--out", default="results/eval.json")
    a = ap.parse_args()

    rows = [run(s, a.trees, a.fp_budget) for s in range(1, a.seeds + 1)]
    print("| seed | caught | false pos | fp rate | incidents | attack -> incidents | severity | ms/event |")
    print("|---|---|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['seed']} | {r['caught']}/{r['attack_events']} | {r['false_positives']}/{r['normal_events']} | "
              f"{r['fp_rate']:.2%} | {r['incidents']} | {r['attack_incidents']} | {r['attack_severity']} | {r['score_ms_per_event']} |")
    summary = {
        "recall_min": min(r["caught"] / r["attack_events"] for r in rows),
        "fp_rate_mean": statistics.mean(r["fp_rate"] for r in rows),
        "fp_rate_max": max(r["fp_rate"] for r in rows),
    }
    print(f"\nrecall (worst seed) {summary['recall_min']:.0%}, fp rate mean {summary['fp_rate_mean']:.2%}, "
          f"max {summary['fp_rate_max']:.2%}")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps({"config": vars(a), "runs": rows, "summary": summary}, indent=2))


if __name__ == "__main__":
    main()
