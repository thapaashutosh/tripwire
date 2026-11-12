"""Train per identity models and publish them.

From real CloudTrail logs (the .json.gz files a trail writes to S3, downloaded locally):
    python -m scripts.train --logs ./cloudtrail-logs --bucket my-tripwire-models --table tripwire-baselines

From the simulator, to try the pipeline without an AWS account history:
    python -m scripts.train --simulate --out results/model.json
"""
from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

from tripwire.events import from_cloudtrail
from tripwire.features import featurize_history
from tripwire.model import train
from tripwire.simulate import generate_week


def load_logs(folder: str):
    events = []
    for p in sorted(Path(folder).rglob("*.json*")):
        opener = gzip.open if p.suffix == ".gz" else open
        with opener(p, "rt") as f:
            for rec in json.load(f).get("Records", []):
                if rec.get("eventCategory", "Management") == "Management":
                    events.append(from_cloudtrail(rec))
    return events


def main() -> None:
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--logs")
    src.add_argument("--simulate", action="store_true")
    ap.add_argument("--fp-budget", type=float, default=0.003)
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument("--out", default="results/model.json")
    ap.add_argument("--bucket")
    ap.add_argument("--key", default="models/latest.json")
    ap.add_argument("--table")
    a = ap.parse_args()

    events = generate_week(1) if a.simulate else load_logs(a.logs)
    stats, X = featurize_history(events)
    models = train(X, n_trees=a.trees, fp_budget=a.fp_budget)
    blob = json.dumps(models)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(blob)
    print(f"{len(events)} events, {len(models) - 1} identity models + global, {len(blob) / 1e6:.1f} MB -> {a.out}")

    if a.bucket:
        import boto3
        boto3.client("s3").put_object(Bucket=a.bucket, Key=a.key, Body=blob.encode(), ContentType="application/json")
        print(f"uploaded s3://{a.bucket}/{a.key}")
    if a.table:
        import boto3
        table = boto3.resource("dynamodb").Table(a.table)
        with table.batch_writer() as bw:
            for ident, s in stats.items():
                bw.put_item(Item={"identity": ident, "stats": json.dumps(s.to_dict())})
        print(f"wrote {len(stats)} baselines to {a.table}")


if __name__ == "__main__":
    main()
