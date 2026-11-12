"""Seven rarity features per API call, all relative to the calling identity's own history."""
from __future__ import annotations

import math
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Tuple

from .events import Event

FEATURES = [
    "api_rarity",     # how rarely this identity calls this API
    "ip_rarity",      # ... from this source IP
    "region_rarity",  # ... in this region
    "ua_rarity",      # ... with this user agent
    "hour_rarity",    # ... at this hour of day
    "burst",          # log1p(calls by this identity in the last 10 min)
    "error_burst",    # log1p(failed calls by this identity in the last 10 min)
]
WINDOW_MIN = 10


@dataclass
class IdentityStats:
    n: int = 0
    api: Counter = field(default_factory=Counter)
    ip: Counter = field(default_factory=Counter)
    region: Counter = field(default_factory=Counter)
    ua: Counter = field(default_factory=Counter)
    hour: List[int] = field(default_factory=lambda: [0] * 24)

    def add(self, e: Event) -> None:
        self.n += 1
        self.api[e.api] += 1
        self.ip[e.ip] += 1
        self.region[e.region] += 1
        self.ua[e.ua] += 1
        self.hour[e.hour] += 1

    def to_dict(self) -> dict:
        return {"n": self.n, "api": dict(self.api), "ip": dict(self.ip), "region": dict(self.region),
                "ua": dict(self.ua), "hour": list(self.hour)}

    @classmethod
    def from_dict(cls, d: dict) -> "IdentityStats":
        return cls(n=int(d.get("n", 0)), api=Counter({k: int(v) for k, v in d.get("api", {}).items()}),
                   ip=Counter({k: int(v) for k, v in d.get("ip", {}).items()}),
                   region=Counter({k: int(v) for k, v in d.get("region", {}).items()}),
                   ua=Counter({k: int(v) for k, v in d.get("ua", {}).items()}),
                   hour=[int(x) for x in d.get("hour", [0] * 24)])


def build_stats(events: Iterable[Event]) -> Dict[str, IdentityStats]:
    stats: Dict[str, IdentityStats] = defaultdict(IdentityStats)
    for e in events:
        stats[e.identity].add(e)
    return dict(stats)


def _rarity(counter: Counter, key: str, n: int, self_count: int) -> float:
    # self_count=1 when scoring an event that is already in the history (leave one out),
    # so a one-off IP in training looks exactly as new as an attacker's IP at scoring time
    c = counter.get(key, 0) - self_count
    return -math.log((c + 1) / (n - self_count + 1))


def _hour_rarity(s: IdentityStats, h: int, self_count: int) -> float:
    def at(i: int) -> float:
        i %= 24
        return s.hour[i] - (self_count if i == h else 0)
    smooth = 0.5 * at(h) + 0.25 * at(h - 1) + 0.25 * at(h + 1)
    return -math.log((smooth + 0.5) / (s.n - self_count + 12))


def window_counts(times: Sequence[float], errors: Sequence[int], t: float) -> Tuple[float, float]:
    """times sorted ascending, errors = prefix sums of error flags aligned with times."""
    lo = bisect_right(times, t - WINDOW_MIN)
    hi = bisect_right(times, t)
    calls = hi - lo
    errs = (errors[hi - 1] if hi else 0) - (errors[lo - 1] if lo else 0)
    return math.log1p(calls), math.log1p(errs)


class Timeline:
    """Per identity sorted call times, for the burst features."""

    def __init__(self, events: Iterable[Event]):
        evs = sorted(events, key=lambda e: e.t)
        self.times = [e.t for e in evs]
        self.err_prefix: List[int] = []
        run = 0
        for e in evs:
            run += int(e.error)
            self.err_prefix.append(run)

    def counts(self, t: float) -> Tuple[float, float]:
        return window_counts(self.times, self.err_prefix, t)


def featurize(e: Event, s: IdentityStats, timeline: Timeline, in_history: bool = False) -> List[float]:
    k = 1 if in_history else 0
    burst, err = timeline.counts(e.t)
    return [
        _rarity(s.api, e.api, s.n, k),
        _rarity(s.ip, e.ip, s.n, k),
        _rarity(s.region, e.region, s.n, k),
        _rarity(s.ua, e.ua, s.n, k),
        _hour_rarity(s, e.hour, k),
        burst,
        err,
    ]


def featurize_history(events: Sequence[Event]) -> Tuple[Dict[str, IdentityStats], Dict[str, List[List[float]]]]:
    """Training matrix per identity, built leave one out from the history itself."""
    stats = build_stats(events)
    by_id: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        by_id[e.identity].append(e)
    X: Dict[str, List[List[float]]] = {}
    for ident, evs in by_id.items():
        tl = Timeline(evs)
        X[ident] = [featurize(e, stats[ident], tl, in_history=True) for e in evs]
    return stats, X

