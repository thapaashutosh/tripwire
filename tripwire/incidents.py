"""Flagged calls -> incidents -> one Slack message each."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .events import Event

# CloudTrail eventName -> MITRE ATT&CK technique (Enterprise, cloud)
MITRE: Dict[str, tuple] = {
    "GetCallerIdentity": ("T1033", "System Owner/User Discovery"),
    "ListBuckets": ("T1619", "Cloud Storage Object Discovery"),
    "ListObjectsV2": ("T1619", "Cloud Storage Object Discovery"),
    "ListUsers": ("T1087.004", "Account Discovery: Cloud Account"),
    "ListRoles": ("T1087.004", "Account Discovery: Cloud Account"),
    "DescribeInstances": ("T1580", "Cloud Infrastructure Discovery"),
    "GetSecretValue": ("T1555.006", "Credentials from Password Stores: Cloud Secrets Management Stores"),
    "GetParameter": ("T1555.006", "Credentials from Password Stores: Cloud Secrets Management Stores"),
    "CreateAccessKey": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "CreateLoginProfile": ("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    "AttachUserPolicy": ("T1098.003", "Account Manipulation: Additional Cloud Roles"),
    "AttachRolePolicy": ("T1098.003", "Account Manipulation: Additional Cloud Roles"),
    "PutUserPolicy": ("T1098.003", "Account Manipulation: Additional Cloud Roles"),
    "RunInstances": ("T1578.002", "Modify Cloud Compute Infrastructure: Create Cloud Instance"),
    "StopLogging": ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs"),
    "DeleteTrail": ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs"),
    "ConsoleLogin": ("T1078.004", "Valid Accounts: Cloud Accounts"),
}
SEVERE = {"T1098.001", "T1098.003", "T1562.008", "T1555.006", "T1578.002"}
GAP_MIN = 30  # a new incident starts after 30 quiet minutes


@dataclass
class Incident:
    identity: str
    ip: str
    events: List[Event] = field(default_factory=list)
    new_ip: bool = False
    new_regions: List[str] = field(default_factory=list)
    new_ua: bool = False

    @property
    def key(self) -> str:
        return f"{self.identity}#{self.ip}"

    @property
    def techniques(self) -> List[tuple]:
        seen, out = set(), []
        for e in self.events:
            m = MITRE.get(e.api)
            if m and e.api not in seen:
                seen.add(e.api)
                out.append((m[0], e.api, e.error))
        return out

    @property
    def severity(self) -> str:
        if any(t in SEVERE for t, _, _ in self.techniques) or (len(self.events) >= 5 and self.new_ip):
            return "HIGH"
        if len(self.events) >= 3 or self.new_ip:
            return "MEDIUM"
        return "LOW"

    @property
    def key_ids(self) -> List[str]:
        return sorted({e.key_id for e in self.events if e.key_id})


def group(flagged: Iterable[Event], stats: Optional[dict] = None) -> List[Incident]:
    """Group by identity + source IP; split when there's a 30 minute gap."""
    open_: Dict[str, Incident] = {}
    done: List[Incident] = []
    for e in sorted(flagged, key=lambda x: x.t):
        k = f"{e.identity}#{e.ip}"
        inc = open_.get(k)
        if inc and e.t - inc.events[-1].t > GAP_MIN:
            done.append(inc)
            inc = None
        if inc is None:
            inc = open_[k] = Incident(e.identity, e.ip)
        inc.events.append(e)
    done.extend(open_.values())
    if stats:
        for inc in done:
            s = stats.get(inc.identity)
            if s is None:
                inc.new_ip, inc.new_ua = True, True
                continue
            inc.new_ip = s.ip.get(inc.ip, 0) == 0
            inc.new_regions = sorted({e.region for e in inc.events if s.region.get(e.region, 0) == 0})
            inc.new_ua = any(s.ua.get(e.ua, 0) == 0 for e in inc.events)
    rank = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
    return sorted(done, key=lambda i: (rank[i.severity], len(i.events)), reverse=True)


def facts(inc: Incident) -> str:
    """Plain text facts. This is what Bedrock gets, and the fallback if Bedrock is down."""
    e0, en = inc.events[0], inc.events[-1]
    lines = [
        f"{inc.severity}: {inc.identity} from {inc.ip}" + (" (first time seen for this identity)" if inc.new_ip else ""),
        f"{len(inc.events)} flagged calls over {en.t - e0.t:.1f} minutes",
        f"regions: {', '.join(sorted({e.region for e in inc.events}))}"
        + (f" (new: {', '.join(inc.new_regions)})" if inc.new_regions else ""),
    ]
    if inc.new_ua:
        lines.append(f"user agent never seen before: {e0.ua}")
    for tech, api, err in inc.techniques:
        lines.append(f"{tech:<10} {api}{'  (AccessDenied)' if err else ''}")
    if inc.key_ids:
        lines.append(f"access key(s) used: {', '.join(inc.key_ids)}")
    return "\n".join(lines)


def action(inc: Incident) -> str:
    if inc.severity != "HIGH":
        return f"Check with the owner of {inc.identity} before acting."
    if inc.key_ids:
        return f"Deactivate and rotate {', '.join(inc.key_ids)} ({inc.identity}) now."
    return f"Revoke active sessions for role {inc.identity} now."


BEDROCK_PROMPT = """You are writing a Slack alert for an on-call engineer about suspicious AWS activity.
Write 2 or 3 short sentences: what likely happened and why it matters. Plain words, no preamble,
no markdown headers, do not invent details that are not in the facts.

Facts:
{facts}"""


def slack_text(inc: Incident, summary: Optional[str] = None) -> str:
    body = summary.strip() if summary else "Summary unavailable, raw facts below."
    return f"*{inc.severity}* tripwire: `{inc.identity}` from `{inc.ip}`\n{body}\n```{facts(inc)}```\n*Do this:* {action(inc)}"
