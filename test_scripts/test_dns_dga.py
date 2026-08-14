#!/usr/bin/env python3
"""
Sends a burst of DNS queries shaped like DGA "domain hunting" behavior - many
distinct, short-but-high-entropy random domain names, almost all resulting in
NXDOMAIN - directly at a target DNS server, to exercise the dns_threat_alerts
Gateway workflow's DGA detector end-to-end (real DNS traffic -> BDDS dnstap ->
Gateway ingest -> alert), not just a synthetic JSON POST to the ingest API.

Uses ".invalid" (an RFC 2606 / RFC 6761 reserved TLD, guaranteed to always
return NXDOMAIN in a compliant resolver) as the default suffix, so the
NXDOMAIN-ratio signal is reliable regardless of whether some other made-up
test domain happens to be registered/wildcarded by someone.

Requires: pip install dnspython

Example:
    python test_dns_dga.py --server 10.0.0.53 --count 40
"""
import argparse
import random
import string
import time

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype


def random_label(length: int) -> str:
    # Letters+digits mix targets high per-character Shannon entropy, matching the
    # shape of real DGA families (e.g. Necurs/Conficker-style algorithmic domains).
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", required=True, help="Target DNS server IP (e.g. a BDDS's address)")
    parser.add_argument("--suffix", default="c2-test.invalid", help="Domain suffix random labels are appended to")
    parser.add_argument("--count", type=int, default=40,
                         help="Number of distinct domains to query (>=20 to clear DGA_MIN_DISTINCT_DOMAINS)")
    parser.add_argument("--label-length", type=int, default=16,
                         help="Length of each random label (>=10 to clear DGA_MIN_LABEL_LEN)")
    parser.add_argument("--qtype", default="A", help="Query type to send")
    parser.add_argument("--delay", type=float, default=0.05, help="Seconds to sleep between queries")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-query timeout in seconds")
    args = parser.parse_args()

    suffix = args.suffix.rstrip(".")
    qtype = dns.rdatatype.from_text(args.qtype.upper())

    print("Sending {} DGA-shaped queries to {} under *.{}".format(args.count, args.server, suffix))
    print("label length: {}".format(args.label_length))

    rcode_counts = {}
    for i in range(args.count):
        label = random_label(args.label_length)
        qname = "{}.{}.".format(label, suffix)
        try:
            query = dns.message.make_query(qname, qtype)
            response = dns.query.udp(query, args.server, timeout=args.timeout)
            rcode = dns.rcode.to_text(response.rcode())
        except Exception as e:  # noqa: BLE001 - this is a test script, any failure just gets logged and skipped
            rcode = "error: {}".format(e)
        rcode_counts[rcode] = rcode_counts.get(rcode, 0) + 1
        print("  [{}/{}] {} -> {}".format(i + 1, args.count, qname, rcode))
        if args.delay:
            time.sleep(args.delay)

    print()
    print("Done. Response code summary:", rcode_counts)
    print("Check the DNS Tunneling/DGA Threat Alerts page (or GET /dns_tunneling_dga_threat_alerts/v1/alerts) for a 'dga' alert "
          "once BDDS's DNS Activity feed catches up - the alert's client IP will be whichever address "
          "this script actually sent from.")


if __name__ == "__main__":
    main()
