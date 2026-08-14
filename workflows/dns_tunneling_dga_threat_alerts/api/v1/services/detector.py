"""
Heuristic tunneling/DGA detection over recently stored DNS activity records.

These are simple, explainable threshold rules (entropy, length, ratio, rate), not a trained
classifier - deliberately so, since there's rarely a labeled attack corpus available to train
against in a typical deployment. Thresholds come from runtime_config.get_config()
(utils/constants.py's TUNNEL_*/DGA_* values seed the defaults there, but are editable
per-environment via the DNS Tunneling/DGA Threat Alerts page's config panels without a code
change or redeploy).

Stored records only carry `domain` itself, not apex/qlen/label_len/label_entropy - those are
cheap pure functions of `domain`, computed here once per distinct domain per detection pass
rather than once per stored record, to keep per-record storage as small as possible at high
query volume. See parser.py's apex_domain/leftmost_label/shannon_entropy.
"""
import time

from . import runtime_config, storage
from .parser import apex_domain, leftmost_label, shannon_entropy


def compute_alerts(window_minutes: int = None) -> list:
    cfg = runtime_config.get_config()
    tunnel_cfg, dga_cfg = cfg["tunneling"], cfg["dga"]
    tunnel_window = window_minutes or tunnel_cfg["window_minutes"]
    dga_window = window_minutes or dga_cfg["window_minutes"]
    now = time.time()
    lookback_minutes = max(tunnel_window, dga_window)
    records = list(storage.read_window(now - lookback_minutes * 60, now))

    alerts = []
    alerts.extend(_detect_tunneling(records, now, tunnel_window, tunnel_cfg))
    alerts.extend(_detect_dga(records, now, dga_window, dga_cfg))
    alerts.sort(key=lambda a: a["last_seen"], reverse=True)
    return alerts


def _detect_tunneling(records: list, now: float, window_minutes: int, cfg: dict) -> list:
    cutoff = now - window_minutes * 60
    suspicious_qtypes = frozenset(cfg["suspicious_qtypes"])
    groups = {}
    for r in records:
        if r.get("kind") != "query" or r["ts"] < cutoff or not r.get("domain") or not r.get("client"):
            continue
        domain = r["domain"]
        apex = apex_domain(domain)
        if not apex:
            continue
        key = (r["client"], apex)
        g = groups.setdefault(key, {
            "count": 0, "qtype_counts": {}, "subdomains": set(), "qlen_sum": 0,
            "first": r["ts"], "last": r["ts"], "server": r.get("server"),
        })
        g["count"] += 1
        qtype = r.get("qtype")
        g["qtype_counts"][qtype] = g["qtype_counts"].get(qtype, 0) + 1
        g["subdomains"].add(domain)
        g["qlen_sum"] += len(domain)
        g["first"] = min(g["first"], r["ts"])
        g["last"] = max(g["last"], r["ts"])

    alerts = []
    for (client, apex), g in groups.items():
        if g["count"] < cfg["min_queries"]:
            continue
        suspicious = sum(v for qt, v in g["qtype_counts"].items() if qt in suspicious_qtypes)
        qtype_ratio = suspicious / g["count"]
        unique_subdomains = len(g["subdomains"])
        avg_qlen = g["qlen_sum"] / g["count"]

        reasons = []
        if qtype_ratio >= cfg["qtype_ratio_threshold"]:
            reasons.append("{:.0%} of queries use {}".format(qtype_ratio, "/".join(sorted(suspicious_qtypes))))
        if unique_subdomains >= cfg["unique_subdomain_threshold"]:
            reasons.append("{} unique subdomains queried".format(unique_subdomains))
        if avg_qlen >= cfg["avg_qlen_threshold"]:
            reasons.append("average query name length {:.0f} chars".format(avg_qlen))
        if g["count"] >= cfg["query_rate_threshold"]:
            reasons.append("{} queries in {} min".format(g["count"], window_minutes))
        if not reasons:
            continue

        alerts.append({
            "type": "tunneling",
            "client": client,
            "domain": apex,
            "server": g["server"],
            "query_count": g["count"],
            "unique_subdomains": unique_subdomains,
            "qtype_ratio": round(qtype_ratio, 3),
            "avg_qlen": round(avg_qlen, 1),
            "reasons": reasons,
            "first_seen": g["first"],
            "last_seen": g["last"],
        })
    return alerts


def _domain_state(domain: str, ts: float) -> dict:
    label = leftmost_label(domain)
    return {
        "entropy": round(shannon_entropy(label), 3), "label_len": len(label),
        "rcode": None, "first": ts, "last": ts,
    }


def _detect_dga(records: list, now: float, window_minutes: int, cfg: dict) -> list:
    cutoff = now - window_minutes * 60
    per_client = {}
    for r in records:
        if r["ts"] < cutoff or not r.get("client") or not r.get("domain"):
            continue
        domain = r["domain"]
        client_state = per_client.setdefault(r["client"], {"domains": {}, "server": r.get("server")})
        domains = client_state["domains"]
        if domain in domains:
            d = domains[domain]
        else:
            d = domains[domain] = _domain_state(domain, r["ts"])
        d["first"] = min(d["first"], r["ts"])
        d["last"] = max(d["last"], r["ts"])
        if r.get("kind") == "response" and r.get("rcode"):
            d["rcode"] = r["rcode"]

    alerts = []
    for client, state in per_client.items():
        domains = state["domains"]
        distinct_count = len(domains)
        if distinct_count < cfg["min_distinct_domains"]:
            continue

        nx_count = sum(1 for d in domains.values() if d["rcode"] and "nxdomain" in d["rcode"].lower())
        nx_ratio = nx_count / distinct_count
        avg_entropy = sum(d["entropy"] for d in domains.values()) / distinct_count
        high_entropy = [
            name for name, d in domains.items()
            if d["label_len"] >= cfg["min_label_len"] and d["entropy"] >= cfg["entropy_threshold"]
        ]

        if nx_ratio < cfg["nxdomain_ratio_threshold"] and avg_entropy < cfg["avg_entropy_threshold"]:
            continue

        reasons = []
        if nx_ratio >= cfg["nxdomain_ratio_threshold"]:
            reasons.append("{:.0%} NXDOMAIN across {} distinct domains".format(nx_ratio, distinct_count))
        if avg_entropy >= cfg["avg_entropy_threshold"]:
            reasons.append("average label entropy {:.2f} bits/char".format(avg_entropy))
        if high_entropy:
            reasons.append("{} high-entropy domain names".format(len(high_entropy)))

        alerts.append({
            "type": "dga",
            "client": client,
            "server": state["server"],
            "distinct_domains": distinct_count,
            "nxdomain_ratio": round(nx_ratio, 3),
            "avg_entropy": round(avg_entropy, 3),
            "reasons": reasons,
            "sample_domains": sorted(domains.keys())[:10],
            "first_seen": min(d["first"] for d in domains.values()),
            "last_seen": max(d["last"] for d in domains.values()),
        })
    return alerts
