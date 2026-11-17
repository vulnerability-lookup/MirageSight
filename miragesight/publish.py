import argparse
import sys

from pyvulnerabilitylookup import PyVulnerabilityLookup

from miragesight import config
from miragesight.feed import ExploitedCVE, fetch, parse
from miragesight.monitoring import heartbeat, log

SIGHTING_TYPE = "exploited"


def sighting_source(row: ExploitedCVE) -> str:
    """The source label of a sighting.

    The feed is a rolling 7-day window: a CVE stays in it for days after its
    last hit. The day in the label is therefore the day of ``last_seen``, never
    the day of the run, so that every daily run of an unchanged row produces the
    same label and is rejected as a duplicate by Vulnerability-Lookup, which
    deduplicates a non-URL source on (vulnerability, source, type, UTC day).

    The label must stay stable: no counters in it, and no URL (a URL source is
    deduplicated whatever the date, which would record each CVE only once).
    """
    return f"OffSeq Mirage (cves-7d) - ({row.last_seen:%Y-%m-%d})"


def sighting_content(row: ExploitedCVE) -> str:
    """Context of the observation, kept out of the source label on purpose."""
    return (
        f"{row.name}\n"
        f"Attempts: {row.attempts}, distinct source IPs: {row.sources} "
        f"(from {row.first_seen:%Y-%m-%dT%H:%M:%SZ} to {row.last_seen:%Y-%m-%dT%H:%M:%SZ}, "
        f"last 7 days)\n"
        f"OffSeq Mirage Feed, TLP:CLEAR, CC BY 4.0: {config.feed_url}"
    )


def build_sighting(row: ExploitedCVE) -> dict:
    return {
        "type": SIGHTING_TYPE,
        "source": sighting_source(row),
        "vulnerability": row.cve,
        "creation_timestamp": row.last_seen,
        "content": sighting_content(row),
    }


def push_sightings(rows: list[ExploitedCVE], dry_run: bool = False) -> None:
    vuln_lookup = None
    if not dry_run:
        vuln_lookup = PyVulnerabilityLookup(
            config.vulnerability_lookup_base_url, token=config.vulnerability_auth_token
        )
    for row in rows:
        sighting = build_sighting(row)
        if vuln_lookup is None:
            print(f"[dry run] {sighting['vulnerability']}: {sighting['source']}")
            continue
        try:
            r = vuln_lookup.create_sighting(sighting=sighting)
        except Exception as e:
            print(f"Error when sending the sighting for {row.cve}:\n{e}")
            log("error", f"push_sightings: {row.cve}: {e}")
            continue
        if "message" in r:
            print(f"{row.cve}: {r['message']}")
            level = "info" if "duplicate" in r["message"].lower() else "warning"
            log(level, f"push_sightings: {row.cve}: {r['message']}")
        else:
            print(f"{row.cve}: sighting created.")


def main():
    parser = argparse.ArgumentParser(
        prog="MirageSight",
        description="A client that retrieves the CVEs exploited against the OffSeq Mirage honeypot fleet "
        "and pushes them to a Vulnerability-Lookup instance as sightings.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the sightings without pushing them to Vulnerability-Lookup.",
    )
    args = parser.parse_args()

    log("info", "Starting MirageSight…")
    heartbeat()

    try:
        content = fetch()
    except Exception as e:
        print(f"Error when fetching the feed {config.feed_url}:\n{e}")
        log("error", f"fetch: {e}")
        sys.exit(1)

    rows, errors = parse(content)
    for error in errors:
        print(f"Skipped row, {error}")
        log("warning", f"parse: {error}")
    print(f"{len(rows)} exploited CVEs in the feed.")

    push_sightings(rows, dry_run=args.dry_run)

    log("info", "MirageSight execution completed.")


if __name__ == "__main__":
    main()
