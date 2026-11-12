"""Synthetic CloudTrail traffic for five identities, plus a stolen key attack.

Documentation IP ranges only (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and AWS's own
example access keys. Nothing here points at a real account.
"""
from __future__ import annotations

import math
import random
from typing import Callable, List, Optional, Sequence, Tuple

from .events import Event

Weighted = Sequence[Tuple[str, float]]


class Identity:
    def __init__(self, name: str, per_week: int, session: float, err: float, key: str,
                 hour: Callable[[random.Random], float], apis: Weighted, ips: Weighted,
                 regions: Weighted, uas: Weighted, novel_ip: float = 0.0, novel_region: float = 0.0):
        self.__dict__.update(locals())
        del self.__dict__["self"]


def _gauss_hour(r: random.Random, mu: float, sd: float) -> float:
    return r.gauss(mu, sd) % 24


IDENTITIES = [
    Identity("ci-deploy", 900, 6, 0.01, "",
             lambda r: 8 + r.random() * 14,
             [("PutObject", 5), ("DescribeStacks", 3), ("AssumeRoleWithWebIdentity", 3), ("UpdateFunctionCode", 2),
              ("GetObject", 2), ("CreateChangeSet", 1), ("ExecuteChangeSet", 1), ("GetParameter", 1)],
             [(f"198.51.100.{i}", 1) for i in range(1, 41)],
             [("us-east-1", 8), ("us-west-2", 2)],
             [("aws-cli/2.15.30 Python/3.11.8 Linux/6.5 GitHubActions", 1)]),
    Identity("svc-reporting", 1100, 4, 0.002, "AKIAIOSFODNN7EXAMPLE",
             lambda r: 7 + r.random() * 11 if r.random() < 0.7 else 1 + r.random(),
             [("GetObject", 6), ("ListObjectsV2", 4), ("PutObject", 3), ("GetQueryResults", 3),
              ("StartQueryExecution", 2), ("ListBuckets", 0.2)],
             [("192.0.2.10", 5), ("192.0.2.11", 5)],
             [("us-east-1", 1)],
             [("Boto3/1.34.69 Python/3.12.2 Linux/5.10 Botocore/1.34.69", 1)]),
    Identity("ashu-dev", 1200, 5, 0.03, "AKIAI44QH8DHBEXAMPLE",
             lambda r: _gauss_hour(r, 15, 3) if r.random() < 0.6 else _gauss_hour(r, 21, 1.5),
             [("GetLogEvents", 4), ("DescribeInstances", 3), ("GetObject", 3), ("DescribeLogStreams", 3),
              ("ListBuckets", 2), ("GetFunction", 2), ("Invoke", 2), ("PutObject", 1), ("DescribeSecurityGroups", 1),
              ("GetCallerIdentity", 0.8), ("ConsoleLogin", 0.5), ("ListUsers", 0.3)],
             [("192.0.2.50", 6), ("192.0.2.51", 3), ("192.0.2.52", 1)],
             [("us-east-1", 9), ("us-west-2", 1)],
             [("aws-cli/2.15.30 Python/3.11.8 Darwin/23.4.0", 3), ("console.amazonaws.com", 2)],
             novel_ip=0.02, novel_region=0.01),
    Identity("lambda-ingest", 1500, 2, 0.001, "",
             lambda r: r.random() * 24,
             [("PutItem", 6), ("GetItem", 3), ("PutObject", 2), ("Query", 2)],
             [("192.0.2.20", 1)],
             [("us-east-1", 1)],
             [("Boto3/1.34.69 Python/3.12 exec-env/AWS_Lambda_python3.12", 1)]),
    Identity("ops-oncall", 300, 3, 0.04, "AKIAJ7Q3EXAMPLEOPS01",
             lambda r: _gauss_hour(r, 13, 5),
             [("DescribeServices", 2), ("UpdateService", 2), ("GetLogEvents", 2), ("DescribeInstances", 2),
              ("GetSecretValue", 0.5), ("AttachRolePolicy", 0.3), ("CreateAccessKey", 0.1)],
             [("192.0.2.60", 4), ("192.0.2.61", 1)],
             [("us-east-1", 1)],
             [("console.amazonaws.com", 3), ("aws-cli/2.15.30 Python/3.11.8 Windows/10", 1)],
             novel_ip=0.05),
]
KEYS = {i.name: i.key for i in IDENTITIES}


def _pick(r: random.Random, items: Weighted) -> str:
    total = sum(w for _, w in items)
    x = r.random() * total
    for v, w in items:
        x -= w
        if x <= 0:
            return v
    return items[-1][0]


def generate_week(seed: int, start: float = 0.0, identities: Optional[List[Identity]] = None) -> List[Event]:
    """One week of normal traffic, 5,000 events with the default identities."""
    r = random.Random(seed)
    out: List[Event] = []
    novel = 0
    week = 7 * 1440
    for ident in identities or IDENTITIES:
        made = 0
        while made < ident.per_week:
            day = r.randrange(7)
            t = day * 1440 + ident.hour(r) * 60
            size = min(ident.per_week - made, 1 + int(-math.log(1 - r.random()) * (ident.session - 1)))
            ip, region = _pick(r, ident.ips), _pick(r, ident.regions)
            if ident.novel_ip and r.random() < ident.novel_ip:
                ip = f"192.0.2.{120 + novel % 120}"
                novel += 1
            if ident.novel_region and r.random() < ident.novel_region:
                region = "eu-west-1"
            ua = _pick(r, ident.uas)
            for _ in range(size):
                out.append(Event(t=start + min(t, week - 1e-3), identity=ident.name, api=_pick(r, ident.apis), ip=ip,
                                 region=region, ua=ua, error=r.random() < ident.err, key_id=ident.key))
                t += r.random() * 1.5
                made += 1
    out.sort(key=lambda e: e.t)
    return out


ATTACK_UA = "aws-cli/2.13.0 Python/3.11.4 Linux/6.1.0-kali7-amd64"
ATTACK_STEPS = [
    # minutes after start, api, region, denied
    (0.0, "GetCallerIdentity", "us-east-1", False),
    (0.4, "ListBuckets", "us-east-1", False),
    (0.9, "ListUsers", "us-east-1", True),
    (1.6, "GetSecretValue", "us-east-1", True),
    (2.3, "DescribeInstances", "ap-southeast-1", False),
    (3.1, "CreateAccessKey", "us-east-1", False),
    (3.8, "AttachUserPolicy", "us-east-1", True),
    (4.9, "RunInstances", "ap-southeast-1", False),
    (6.2, "StopLogging", "us-east-1", False),
]


def stolen_key_attack(start: float, identity: str = "svc-reporting", ip: str = "203.0.113.42") -> List[Event]:
    """The kind of thing that happens after a key lands in a public repo: who am I, what can I
    see, grab secrets, make a backdoor key, start miners, turn off logging."""
    return [Event(t=start + dt, identity=identity, api=api, ip=ip, region=region, ua=ATTACK_UA,
                  error=denied, key_id=KEYS.get(identity, ""), attack=True)
            for dt, api, region, denied in ATTACK_STEPS]
