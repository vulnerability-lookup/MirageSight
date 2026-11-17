"""Fetch and parse the OffSeq Mirage Feed list of exploited CVEs."""

import csv
import io
import re
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from miragesight import config

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass
class ExploitedCVE:
    cve: str
    name: str
    kev: bool
    attempts: int
    sources: int
    first_seen: datetime
    last_seen: datetime


def fetch(url: str | None = None, timeout: int = 60) -> str:
    """Download the CSV file of the feed."""
    request = urllib.request.Request(
        url or config.feed_url, headers={"User-Agent": config.user_agent}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 UTC timestamp such as 2026-11-16T23:00:00Z."""
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse(content: str) -> tuple[list[ExploitedCVE], list[str]]:
    """Parse the CSV content. Returns the valid rows and a list of errors for the others."""
    rows, errors = [], []
    for line, row in enumerate(csv.DictReader(io.StringIO(content)), start=2):
        try:
            cve = row["cve"].strip().upper()
            if not CVE_PATTERN.match(cve):
                raise ValueError(f"not a CVE ID: {row['cve']!r}")
            rows.append(
                ExploitedCVE(
                    cve=cve,
                    name=(row.get("name") or "").strip(),
                    kev=(row.get("kev") or "").strip().lower() == "true",
                    attempts=int(row["attempts"]),
                    sources=int(row["sources"]),
                    first_seen=parse_timestamp(row["first_seen"]),
                    last_seen=parse_timestamp(row["last_seen"]),
                )
            )
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            errors.append(f"line {line}: {e}")
    return rows, errors
