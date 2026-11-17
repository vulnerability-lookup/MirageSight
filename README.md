# MirageSight

A client that retrieves the CVEs exploited against the honeypot fleet of the
[OffSeq Mirage Feed](https://feeds.offseq.com/) and sends them to the
[Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) API as sightings
of type `exploited`.

The feed is free, rebuilt daily, marked TLP:CLEAR and published under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
MirageSight reads [cves-7d.csv](https://feeds.offseq.com/mirage-feed/latest/cves-7d.csv):
one row per CVE exploited against the sensors in the last 7 days.


## How sightings are built

- One `exploited` sighting per CVE and per day of activity.
- The source is `OffSeq Mirage (cves-7d) - (<day>)`, where `<day>` is the UTC day of the row's
  `last_seen`, and `creation_timestamp` is `last_seen`.
- The content holds the exploit name, the attempt count and the number of distinct source IPs.

The feed is a rolling 7-day window, so a CVE stays in it for days after its last hit.
Since the label is dated with `last_seen` and not with the day of the run, a row that did not change
gives the same sighting every day, and Vulnerability-Lookup rejects it as a duplicate.
A CVE seen again on a later day gives one new sighting.
Running MirageSight twice, or missing a run, therefore creates no duplicates. After several missed
days only the most recent day of activity is recorded, since the feed gives no per-day detail.

Run it once a day, after the feed is rebuilt (around 03:00 UTC).


## Installation

[pipx](https://github.com/pypa/pipx) is an easy way to install and run Python applications in isolated environments.
It's easy to [install](https://github.com/pypa/pipx?tab=readme-ov-file#on-linux).

```bash
$ pipx install MirageSight
$ export MIRAGESIGHT_CONFIG=~/.MirageSight/conf.py
```

The configuration should be defined in a Python file (e.g., ``~/.MirageSight/conf.py``).
You must then set an environment variable (``MIRAGESIGHT_CONFIG``) with the full path to this file.

You can have a look at [this example](https://github.com/vulnerability-lookup/MirageSight/blob/main/miragesight/conf_sample.py) of configuration.


### With Docker

```bash
git clone https://github.com/vulnerability-lookup/MirageSight
cd MirageSight

# Make sure miragesight/conf.py exists before running
docker compose up --build
```

> [!NOTE]
> The docker-compose.yml expects a `miragesight/conf.py` file.
> You can create it from the provided example:
>
> ```bash
> $ cp miragesight/conf_sample.py miragesight/conf.py
> ```

The container runs once and exits. Schedule `docker compose up` once a day.


## Usage

```bash
$ MirageSight --help
usage: MirageSight [-h] [--dry-run]

A client that retrieves the CVEs exploited against the OffSeq Mirage honeypot fleet and pushes them to a
Vulnerability-Lookup instance as sightings.

options:
  -h, --help  show this help message and exit
  --dry-run   Print the sightings without pushing them to Vulnerability-Lookup.
```

For example, with cron:

```
30 4 * * * MIRAGESIGHT_CONFIG=~/.MirageSight/conf.py ~/.local/bin/MirageSight
```


## License

[MirageSight](https://github.com/vulnerability-lookup/MirageSight) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2026 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2026 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~

The data of the OffSeq Mirage Feed is published by OffSeq under CC BY 4.0.
