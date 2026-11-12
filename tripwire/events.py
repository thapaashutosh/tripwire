"""CloudTrail record -> the small Event the detector cares about."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Event:
    t: float            # minutes since epoch (UTC)
    identity: str
    api: str
    ip: str
    region: str
    ua: str
    error: bool
    key_id: str = ""     # access key used, if any. this is what gets rotated
    event_id: str = ""
    attack: bool = False  # ground truth, only ever set by the simulator

    @property
    def hour(self) -> int:
        return int((self.t % 1440) // 60)


def identity_of(user_identity: dict) -> str:
    kind = user_identity.get("type", "")
    if kind == "IAMUser":
        return user_identity.get("userName") or user_identity.get("arn", "unknown")
    if kind == "AssumedRole":
        issuer = user_identity.get("sessionContext", {}).get("sessionIssuer", {})
        return issuer.get("userName") or user_identity.get("arn", "unknown")
    if kind == "Root":
        return "root"
    return user_identity.get("arn") or user_identity.get("principalId") or kind or "unknown"


def from_cloudtrail(rec: dict) -> Event:
    ts = datetime.strptime(rec["eventTime"], "%Y-%m-%dT%H:%M:%SZ")
    epoch = (ts - datetime(1970, 1, 1)).total_seconds()
    ui = rec.get("userIdentity", {})
    return Event(
        t=epoch / 60.0,
        identity=identity_of(ui),
        api=rec.get("eventName", ""),
        ip=rec.get("sourceIPAddress", ""),
        region=rec.get("awsRegion", ""),
        ua=rec.get("userAgent", ""),
        error=bool(rec.get("errorCode")),
        key_id=ui.get("accessKeyId", ""),
        event_id=rec.get("eventID", ""),
    )
