#!/usr/bin/env python3
"""
Sends a burst of DNS queries shaped like a tunneling exfil pattern - many unique,
long, TXT/NULL/CNAME-heavy subdomains under one base domain - directly at a
target DNS server, to exercise the dns_threat_alerts Gateway workflow's
tunneling detector end-to-end (real DNS traffic -> BDDS dnstap -> Gateway
ingest -> alert), not just a synthetic JSON POST to the ingest API.

Uses ".example." (an RFC 2606 reserved TLD, guaranteed never to resolve for
real) as the default base domain, so this is safe to point at a real
recursive resolver without risk of hitting a live domain.

Requires: pip install dnspython

Example:
    python test_dns_tunneling.py --server 10.0.0.53 --count 80
"""
import argparse
import random
import string
import time

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

# Matches dns_threat_alerts' TUNNEL_SUSPICIOUS_QTYPES default in utils/constants.py.
DEFAULT_QTYPES = "TXT,NULL,CNAME"


def random_label(length: int) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", required=True, help="Target DNS server IP (e.g. a BDDS's address)")
    parser.add_argument("--domain", default="tunnel-test.example", help="Base domain to tunnel data under")
    parser.add_argument("--count", type=int, default=80,
                         help="Number of queries to send (>=30 to clear TUNNEL_MIN_QUERIES, "
                              ">=50 unique subdomains to also clear TUNNEL_UNIQUE_SUBDOMAIN_THRESHOLD)")
    parser.add_argument("--label-length", type=int, default=63,
                         help="Length of each subdomain label, max 63 (DNS label limit) - default "
                              "is chosen so the full qname clears TUNNEL_AVG_QLEN_THRESHOLD (80 chars)")
    parser.add_argument("--qtypes", default=DEFAULT_QTYPES, help="Comma-separated query types to rotate through")
    parser.add_argument("--delay", type=float, default=0.05, help="Seconds to sleep between queries")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-query timeout in seconds")
    args = parser.parse_args()

    if args.label_length > 63:
        parser.error("--label-length must be <= 63 (DNS label length limit)")

    domain = args.domain.rstrip(".")
    qtypes = [t.strip().upper() for t in args.qtypes.split(",") if t.strip()]

    print("Sending {} tunneling-shaped queries to {} under *.{}".format(args.count, args.server, domain))
    print("qtypes: {}, label length: {}".format(qtypes, args.label_length))

    ok, failed = 0, 0
    seen_labels = set()
    for i in range(args.count):
        label = random_label(args.label_length)
        seen_labels.add(label)
        qname = "{}.{}.".format(label, domain)
        qtype = qtypes[i % len(qtypes)]
        try:
            query = dns.message.make_query(qname, dns.rdatatype.from_text(qtype))
            response = dns.query.udp(query, args.server, timeout=args.timeout)
            rcode = dns.rcode.to_text(response.rcode())
            ok += 1
        except Exception as e:  # noqa: BLE001 - this is a test script, any failure just gets logged and skipped
            rcode = "error: {}".format(e)
            failed += 1
        print("  [{}/{}] {} {} (len {}) -> {}".format(i + 1, args.count, qtype, qname, len(qname), rcode))
        if args.delay:
            time.sleep(args.delay)

    print()
    print("Done: {} sent, {} failed, {} unique subdomains.".format(ok, failed, len(seen_labels)))
    print("Check the DNS Tunneling/DGA Threat Alerts page (or GET /dns_tunneling_dga_threat_alerts/v1/alerts) for a 'tunneling' alert "
          "once BDDS's DNS Activity feed catches up - the alert's client IP will be whichever address "
          "this script actually sent from.")


if __name__ == "__main__":
    main()
