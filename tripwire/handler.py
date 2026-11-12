"""Lambda entry point. EventBridge delivers one CloudTrail record per invocation.

Flow: parse -> record call in the recent window table -> 7 features -> score with the identity's
forest -> if anomalous, upsert an incident (identity + source IP) -> first event posts to Slack,
later events edit that same message. One incident, one message.

Baselines and models are written by scripts/train.py, never updated from live traffic here,
so an attacker can't slowly teach the model that their behaviour is normal.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from decimal import Decimal
from typing import Optional

import boto3
from boto3.dynamodb.conditions import Key

from .events import Event, from_cloudtrail
from .features import IdentityStats, Timeline, WINDOW_MIN, featurize
from .incidents import BEDROCK_PROMPT, GAP_MIN, Incident, facts, slack_text
from .model import Detector

log = logging.getLogger()
log.setLevel(logging.INFO)

ddb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
BASELINES = ddb.Table(os.environ.get("BASELINE_TABLE", "tripwire-baselines"))
RECENT = ddb.Table(os.environ.get("RECENT_TABLE", "tripwire-recent"))
INCIDENTS = ddb.Table(os.environ.get("INCIDENT_TABLE", "tripwire-incidents"))

_detector: Optional[Detector] = None
_stats_cache: dict = {}
STATS_TTL_S = 300


def detector() -> Detector:
    global _detector
    if _detector is None:
        obj = s3.get_object(Bucket=os.environ["MODEL_BUCKET"], Key=os.environ.get("MODEL_KEY", "models/latest.json"))
        _detector = Detector(json.loads(obj["Body"].read()))
    return _detector


def stats_for(identity: str) -> Optional[IdentityStats]:
    hit = _stats_cache.get(identity)
    if hit and time.time() - hit[0] < STATS_TTL_S:
        return hit[1]
    item = BASELINES.get_item(Key={"identity": identity}).get("Item")
    s = IdentityStats.from_dict(json.loads(item["stats"])) if item else None
    _stats_cache[identity] = (time.time(), s)
    return s


def recent_timeline(e: Event) -> Timeline:
    RECENT.put_item(Item={
        "identity": e.identity, "t": Decimal(str(round(e.t, 4))), "event_id": e.event_id,
        "err": e.error, "ttl": int(time.time()) + 3600,
    })
    resp = RECENT.query(KeyConditionExpression=Key("identity").eq(e.identity) & Key("t").gte(Decimal(str(e.t - WINDOW_MIN))))
    evs = [Event(t=float(i["t"]), identity=e.identity, api="", ip="", region="", ua="", error=bool(i.get("err")))
           for i in resp["Items"]]
    return Timeline(evs)


def handler(event, _ctx=None):
    rec = event.get("detail", event)
    if "eventName" not in rec:
        return {"skipped": "not a cloudtrail record"}
    e = from_cloudtrail(rec)
    s = stats_for(e.identity)
    tl = recent_timeline(e)
    # never seen identity: every rarity is maxed out, the global forest decides
    x = featurize(e, s, tl) if s else [12.0, 12.0, 12.0, 12.0, 4.0] + featurize(e, IdentityStats(n=1), tl)[5:]
    det = detector()
    score = det.score(e.identity, x)
    anomalous = det.is_anomalous(e.identity, x)
    log.info(json.dumps({"identity": e.identity, "api": e.api, "ip": e.ip, "score": round(score, 4), "flagged": anomalous}))
    if not anomalous:
        return {"flagged": False, "score": score}
    inc_id = upsert_incident(e, s, score)
    return {"flagged": True, "score": score, "incident": inc_id}


# ---------- incidents ----------

def _event_to_item(e: Event, score: float) -> dict:
    return {"t": Decimal(str(round(e.t, 4))), "api": e.api, "region": e.region, "ua": e.ua, "err": e.error,
            "key": e.key_id, "score": Decimal(str(round(score, 4)))}


def _item_to_event(identity: str, ip: str, d: dict) -> Event:
    return Event(t=float(d["t"]), identity=identity, api=d["api"], ip=ip, region=d["region"], ua=d["ua"],
                 error=bool(d["err"]), key_id=d.get("key", ""))


def upsert_incident(e: Event, s: Optional[IdentityStats], score: float) -> str:
    key = f"{e.identity}#{e.ip}"
    item = INCIDENTS.get_item(Key={"key": key}).get("Item")
    if item and e.t - float(item["last_t"]) > GAP_MIN:
        item = None  # old incident went quiet, start a new one
    events = (item["events"] if item else []) + [_event_to_item(e, score)]

    inc = Incident(e.identity, e.ip, [_item_to_event(e.identity, e.ip, d) for d in events])
    if s:
        inc.new_ip = s.ip.get(e.ip, 0) == 0
        inc.new_regions = sorted({x.region for x in inc.events if s.region.get(x.region, 0) == 0})
        inc.new_ua = any(s.ua.get(x.ua, 0) == 0 for x in inc.events)
    else:
        inc.new_ip = inc.new_ua = True

    summary = item.get("summary") if item else None
    if not item or item.get("severity") != inc.severity:
        summary = bedrock_summary(inc) or summary  # only re-summarize when severity changes
    text = slack_text(inc, summary)
    ts = item.get("slack_ts") if item else None
    ts = slack_post(text, ts)

    INCIDENTS.put_item(Item={
        "key": key, "last_t": Decimal(str(round(e.t, 4))), "events": events, "severity": inc.severity,
        "summary": summary or "", "slack_ts": ts or "", "ttl": int(time.time()) + 14 * 86400,
    })
    return key


def bedrock_summary(inc: Incident) -> Optional[str]:
    model = os.environ.get("BEDROCK_MODEL_ID")
    if not model:
        return None
    try:
        br = boto3.client("bedrock-runtime")
        resp = br.converse(
            modelId=model,
            messages=[{"role": "user", "content": [{"text": BEDROCK_PROMPT.format(facts=facts(inc))}]}],
            inferenceConfig={"maxTokens": 200, "temperature": 0.2},
        )
        return resp["output"]["message"]["content"][0]["text"]
    except Exception:  # alerting must not depend on the LLM being up
        log.exception("bedrock summary failed, sending facts only")
        return None


_slack_token: Optional[str] = None


def slack_post(text: str, ts: Optional[str]) -> Optional[str]:
    global _slack_token
    arn = os.environ.get("SLACK_SECRET_ARN")
    if not arn:
        log.info("no slack configured:\n%s", text)
        return ts
    if _slack_token is None:
        _slack_token = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"]
    channel = os.environ.get("SLACK_CHANNEL", "#sec-alerts")
    method = "chat.update" if ts else "chat.postMessage"
    body = {"channel": channel, "text": text, **({"ts": ts} if ts else {})}
    req = urllib.request.Request(f"https://slack.com/api/{method}", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json; charset=utf-8",
                                          "Authorization": f"Bearer {_slack_token}"})
    with urllib.request.urlopen(req, timeout=5) as r:
        out = json.loads(r.read())
    if not out.get("ok"):
        log.error("slack error: %s", out)
        return ts
    return out.get("ts", ts)
