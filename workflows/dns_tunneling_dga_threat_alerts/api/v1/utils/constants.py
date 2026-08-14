"""
Storage paths and detection thresholds for the DNS Tunneling/DGA Threat Alerts workflow.

All thresholds here are heuristic, not ML-derived - they're deliberately named constants so
they can be retuned per-environment without touching detector logic.
"""

# Durable data lives outside the workflow's own code tree, since a typical redeploy replaces
# workflows/dns_tunneling_dga_threat_alerts/ wholesale before recopying code - anything stored
# inside that tree would be wiped by the very redeploy meant to ship a code change.
DATA_DIR = "/bluecat_gateway/dns_tunneling_dga_threat_alerts_data"
EVENTS_DIR = DATA_DIR + "/events"
TOKEN_FILE = DATA_DIR + "/ingest_token.txt"

RETENTION_DAYS = 7

# Only these dnstap messageTypes reflect actual internal-client DNS behavior (the thing we
# care about for tunneling/DGA). Forwarder*/Auth*/Resolver* (BDDS<->upstream, authoritative,
# internal resolver-cache traffic) are dropped at ingest, never written to disk.
ALLOWED_MESSAGE_TYPES = frozenset({"ClientQuery", "ClientResponse"})

# --- Tunneling heuristics (grouped per client + apex domain, over a sliding window) ---
TUNNEL_WINDOW_MINUTES = 10
TUNNEL_MIN_QUERIES = 30  # below this, any ratio-based signal is too noisy to trust
TUNNEL_SUSPICIOUS_QTYPES = frozenset({"TXT", "NULL", "CNAME"})
TUNNEL_QTYPE_RATIO_THRESHOLD = 0.3  # >=30% of queries to one apex domain are suspicious qtypes
TUNNEL_UNIQUE_SUBDOMAIN_THRESHOLD = 50  # unique first-level labels under one apex domain
TUNNEL_AVG_QLEN_THRESHOLD = 80  # avg full domain-name length in chars (typical real names < 40)
TUNNEL_QUERY_RATE_THRESHOLD = 100  # queries to one apex domain from one client, within the window
TUNNEL_MIN_SIGNALS = 2  # how many of the 4 signals above must co-occur before alerting - a
# single signal alone (e.g. just raw query count) is too easily crossed by ordinary heavy
# traffic to a popular domain or a CDN's naturally large edge-subdomain pool

# --- DGA heuristics (per client, over the same sliding window) ---
DGA_WINDOW_MINUTES = 10
DGA_MIN_LABEL_LEN = 10  # shorter labels have high entropy by chance; gate on length too
DGA_ENTROPY_THRESHOLD = 3.5  # Shannon entropy, bits/char, of the leftmost label
DGA_MIN_DISTINCT_DOMAINS = 20  # distinct domains queried by one client in the window
DGA_NXDOMAIN_RATIO_THRESHOLD = 0.8  # fraction of those domains that came back NXDOMAIN
DGA_AVG_ENTROPY_THRESHOLD = 3.3  # average leftmost-label entropy across those distinct domains
