import json
import random

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from tripwire.events import Event, from_cloudtrail
from tripwire.features import FEATURES, Timeline, build_stats, featurize, featurize_history
from tripwire.incidents import group, slack_text
from tripwire.model import ExportedForest, export_sklearn, train
from tripwire.simulate import generate_week, stolen_key_attack


def test_exported_forest_matches_sklearn():
    rng = np.random.RandomState(0)
    X = np.vstack([rng.normal(size=(500, 7)), rng.normal(4, 1, size=(10, 7))])
    f = IsolationForest(n_estimators=50, max_samples=256, random_state=3).fit(X)
    ours = ExportedForest(json.loads(json.dumps(export_sklearn(f))))  # survives a JSON round trip
    expected = -f.score_samples(X)
    got = np.array([ours.score(x) for x in X])
    assert np.allclose(got, expected, atol=1e-12)


def test_cloudtrail_parsing_assumed_role():
    rec = {
        "eventTime": "2026-11-06T09:15:00Z", "eventName": "ListBuckets", "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.9", "userAgent": "aws-cli/2.13.0", "errorCode": "AccessDenied",
        "eventID": "abc",
        "userIdentity": {"type": "AssumedRole", "accessKeyId": "ASIAEXAMPLE",
                         "sessionContext": {"sessionIssuer": {"userName": "svc-reporting"}}},
    }
    e = from_cloudtrail(rec)
    assert (e.identity, e.api, e.error, e.hour, e.key_id) == ("svc-reporting", "ListBuckets", True, 9, "ASIAEXAMPLE")


def _ev(t, ip="192.0.2.1", api="GetObject", err=False):
    return Event(t=t, identity="a", api=api, ip=ip, region="us-east-1", ua="ua", error=err)


def test_leave_one_out_equals_scoring_against_history_without_the_event():
    hist = [_ev(i * 60.0) for i in range(99)] + [_ev(99 * 60.0, ip="192.0.2.99")]
    _, X = featurize_history(hist)
    rest = build_stats(hist[:-1])["a"]
    direct = featurize(hist[-1], rest, Timeline(hist))
    for name in ("api_rarity", "ip_rarity", "region_rarity", "ua_rarity", "hour_rarity"):
        i = FEATURES.index(name)
        assert X["a"][-1][i] == pytest.approx(direct[i]), name


def test_burst_window_counts_last_ten_minutes():
    evs = [_ev(t, err=(t == 9.0)) for t in (0.0, 5.0, 9.0, 9.5, 30.0)]
    tl = Timeline(evs)
    x = featurize(evs[3], build_stats(evs)["a"], tl)
    assert x[FEATURES.index("burst")] == pytest.approx(np.log1p(4))
    assert x[FEATURES.index("error_burst")] == pytest.approx(np.log1p(1))


def test_grouping_one_incident_per_attack_and_gap_split():
    atk = stolen_key_attack(start=1000.0)
    later = stolen_key_attack(start=1000.0 + 120)
    inc = group(atk + later)
    assert len(inc) == 2 and all(len(i.events) == 9 for i in inc)
    assert inc[0].severity == "HIGH"
    text = slack_text(inc[0], "test summary")
    assert "AKIAIOSFODNN7EXAMPLE" in text and "T1562.008" in text


def test_end_to_end_flags_attack_without_peeking():
    hist = generate_week(11)
    stats, X = featurize_history(hist)
    models = train(X, n_trees=60, seed=11)
    from tripwire.model import Detector
    det = Detector(models)
    atk = stolen_key_attack(start=7 * 1440 + 4 * 1440 + 3 * 60 + 12)  # 03:12, outside the nightly batch
    tl = Timeline(atk)
    flagged = [e for e in atk if det.is_anomalous(e.identity, featurize(e, stats[e.identity], tl))]
    assert len(flagged) >= 7
    incidents = group(flagged, stats)
    assert len(incidents) == 1 and incidents[0].severity == "HIGH" and incidents[0].new_ip


def test_simulator_is_deterministic():
    a, b = generate_week(5), generate_week(5)
    assert a == b and len(a) == 5000
    random.seed(0)  # global state must not matter
    assert generate_week(5) == a
