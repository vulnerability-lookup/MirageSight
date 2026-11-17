# For PyVulnerabilityLookup
vulnerability_lookup_base_url = "https://vulnerability.circl.lu/"
vulnerability_auth_token = ""

# OffSeq Mirage Feed: CVEs exploited against the honeypot fleet in the last 7 days.
# TLP:CLEAR, CC BY 4.0. See https://feeds.offseq.com/
feed_url = "https://feeds.offseq.com/mirage-feed/latest/cves-7d.csv"
user_agent = "MirageSight (+https://github.com/vulnerability-lookup/MirageSight)"

# Hearbeat mechanism
heartbeat_enabled = True
valkey_host = "127.0.0.1"
valkey_port = 10002
expiration_period = 93600  # 26 hours
