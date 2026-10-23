import re
from collections import Counter

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAIL_RE = re.compile(r"failed password|authentication failure|login failed|invalid password|failed login", re.I)
SUCCESS_RE = re.compile(r"accepted password|accepted publickey|login successful|authentication success", re.I)
SUDO_RE = re.compile(r"\bsudo\b", re.I)

def analyze_logs(content: str, threshold: int = 5) -> dict:
    lines = content.splitlines()
    failed_by_ip = Counter()
    event_counts = Counter()
    failed_events = 0

    for line in lines:
        is_failed = bool(FAIL_RE.search(line))
        is_success = bool(SUCCESS_RE.search(line))
        if is_failed:
            failed_events += 1
            event_counts["failed_login"] += 1
            match = IP_RE.search(line)
            if match:
                failed_by_ip[match.group(0)] += 1
        if is_success:
            event_counts["successful_login"] += 1
        if SUDO_RE.search(line):
            event_counts["sudo_activity"] += 1

    flagged = {ip: count for ip, count in failed_by_ip.items() if count >= threshold}
    return {
        "line_count": len(lines),
        "failed_events": failed_events,
        "flagged_ips": dict(sorted(flagged.items(), key=lambda item: item[1], reverse=True)),
        "event_counts": dict(event_counts),
    }
