"""Runs the Lambda handler end to end against in-memory fakes of DynamoDB, S3 and Slack."""
import os
from datetime import datetime, timedelta

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import pytest  # noqa: E402

from tripwire import handler as h  # noqa: E402
from tripwire.features import featurize_history  # noqa: E402
from tripwire.model import Detector, train  # noqa: E402
from tripwire.simulate import generate_week, stolen_key_attack  # noqa: E402


class FakeTable:
    def __init__(self, key):
        self.key, self.items = key, {}

    def get_item(self, Key):
        k = Key[self.key]
        return {"Item": self.items[k]} if k in self.items else {}

    def put_item(self, Item):
        if self.key == "identity" and "t" in Item:  # recent table: (identity, t) composite key
            self.items.setdefault(Item["identity"], []).append(Item)
        else:
            self.items[Item[self.key]] = dict(Item)

    def query(self, KeyConditionExpression):
        # pull identity and lower bound back out of the boto3 condition object
        (ident_cond, t_cond) = KeyConditionExpression._values
        ident, lo = ident_cond._values[1], t_cond._values[1]
        return {"Items": [i for i in self.items.get(ident, []) if i["t"] >= lo]}


def record(e):
    ts = datetime(1970, 1, 1) + timedelta(minutes=e.t)
    return {"detail-type": "AWS API Call via CloudTrail", "detail": {
        "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventName": e.api, "awsRegion": e.region,
        "sourceIPAddress": e.ip, "userAgent": e.ua, **({"errorCode": "AccessDenied"} if e.error else {}),
        "eventID": f"evt-{e.t}",
        "userIdentity": {"type": "IAMUser", "userName": e.identity, "accessKeyId": e.key_id},
    }}


@pytest.fixture
def wired(monkeypatch):
    hist = generate_week(3)
    stats, X = featurize_history(hist)
    monkeypatch.setattr(h, "_detector", Detector(train(X, n_trees=60, seed=3)))
    monkeypatch.setattr(h, "_stats_cache", {k: (1e18, v) for k, v in stats.items()})
    monkeypatch.setattr(h, "RECENT", FakeTable("identity"))
    incidents = FakeTable("key")
    monkeypatch.setattr(h, "INCIDENTS", incidents)
    monkeypatch.setattr(h, "bedrock_summary", lambda inc: "Someone is using the reporting key from a new IP.")
    posts = []

    def fake_slack(text, ts):
        posts.append((text, ts))
        return ts or "1730000000.000100"
    monkeypatch.setattr(h, "slack_post", fake_slack)
    return incidents, posts, hist


def test_attack_becomes_one_incident_and_one_slack_thread(wired):
    incidents, posts, _ = wired
    start = 7 * 1440 + 4 * 1440 + 3 * 60 + 12
    results = [h.handler(record(e)) for e in stolen_key_attack(start)]
    assert sum(r["flagged"] for r in results) >= 7
    assert list(incidents.items) == ["svc-reporting#203.0.113.42"]
    inc = incidents.items["svc-reporting#203.0.113.42"]
    assert inc["severity"] == "HIGH"
    # first flagged call posts, every later one edits the same message
    assert posts[0][1] is None and all(ts == "1730000000.000100" for _, ts in posts[1:])
    assert "AKIAIOSFODNN7EXAMPLE" in posts[-1][0]


def test_normal_traffic_mostly_quiet(wired):
    incidents, posts, hist = wired
    normal = generate_week(4, start=7 * 1440)[:500]
    flagged = sum(h.handler(record(e))["flagged"] for e in normal)
    assert flagged <= 5


def test_non_cloudtrail_event_is_ignored(wired):
    assert "skipped" in h.handler({"detail": {"hello": "world"}})
