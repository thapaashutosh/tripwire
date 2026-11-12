"""Poll the incidents table until something HIGH shows up after --since, or fail."""
from __future__ import annotations

import argparse
import sys
import time

import boto3


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", type=float, required=True, help="unix seconds")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--table", default="tripwire-incidents")
    a = ap.parse_args()

    table = boto3.resource("dynamodb").Table(a.table)
    since_min = a.since / 60
    deadline = time.time() + a.timeout
    while time.time() < deadline:
        items = table.scan().get("Items", [])
        hits = [i for i in items if float(i["last_t"]) >= since_min and i.get("severity") == "HIGH"]
        if hits:
            for i in hits:
                print(f"incident {i['key']} severity {i['severity']} with {len(i['events'])} events")
            return
        time.sleep(20)
    print("no HIGH incident before timeout", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
