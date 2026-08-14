# DNS Tunneling / DGA Threat Alerts — BlueCat Gateway Workflow

A [BlueCat Gateway](https://www.bluecatnetworks.com/) custom workflow that ingests BDDS's
**DNS Activity** logging feed and raises heuristic alerts for two DNS-based attack patterns:

- **DNS tunneling** — data smuggled out through DNS queries (long, high-volume, TXT/NULL/CNAME-heavy subdomains under one domain)
- **DGA (Domain Generation Algorithm)** — malware "domain hunting" behavior (many distinct, high-entropy, mostly-NXDOMAIN lookups from one client)

Detection runs entirely inside Gateway — no external SIEM, no agent on the client, no third-party
security product. BDDS streams its DNS Activity feed straight to this workflow over plain HTTP;
the workflow filters, stores, and scores it.

## Why this exists

BlueCat Gateway is a management/orchestration layer (REST calls to BAM/BDDS, SSH to appliances)
— it has no inline visibility into DNS traffic. This workflow doesn't try to fake that. Instead
it consumes the same **DNS Activity (dnstap) feed** BDDS can already export over HTTP, applies a
few explainable threshold rules, and surfaces the result in Gateway's own UI. It's detection +
triage, not a replacement for an inline DPI/security appliance — see "Limitations" below.

## Architecture

```
BDDS (DNS Activity / dnstap) --HTTP POST--> this workflow's ingest endpoint
                                                   |
                                                   v
                                    filter to ClientQuery/ClientResponse,
                                    reduce to {ts, server, client, kind, domain, qtype/rcode}
                                                   |
                                                   v
                              day-bucketed JSONL on disk, 7-day rolling retention,
                              non-today files gzip-compressed automatically
                                                   |
                                                   v
                          on demand: tunneling/DGA heuristics scan the retained window
                                                   |
                                                   v
                                       alerts table in the Gateway UI
```

Nothing is stored except what detection needs: `timestamp, server, client IP, domain, query
type or response code`. Everything else (apex domain, query length, Shannon entropy of the
leftmost label) is a cheap pure function of `domain` and is computed at detection time instead
of being persisted per record.

## Installing

1. Copy `workflows/dns_tunneling_dga_threat_alerts/` into your Gateway's `workflows/` directory
   (however your install manages that — `docker cp` into the container, a filesystem copy, etc.)
   and restart Gateway.
2. Add a page-permission entry to your **custom workspace's** `permissions.json` (this is a
   platform requirement for *any* new Gateway workflow, not specific to this one — without it
   the page exists but never appears in the nav):
   ```json
   "dns_tunneling_dga_threat_alerts": {
     "dns_tunneling_dga_threat_alerts_page": ["all", "admin"]
   }
   ```
3. Open **DNS Tunneling/DGA Threat Alerts** in Gateway's nav. The page generates its own ingest
   token on first load — copy the ready-made **Output URI** shown there (token already embedded
   as a query parameter) into BAM's **DNS Activity Logging → Destination → Type "HTTP"**
   configuration on each BDDS.

   Use plain `http://`, not `https://`. Gateway installs commonly run under Apache/mod_wsgi,
   which strips the `Authorization` header before it reaches any WSGI app unless
   `WSGIPassAuthorization On` is explicitly set — so the ingest token travels as a `?token=`
   query parameter on the Output URI instead, which works regardless of that setting. If your
   install's HTTPS listener uses a cert that regenerates on every container restart (check
   before relying on it), stick to HTTP to avoid re-uploading a CA cert every time Gateway
   restarts.

## What gets detected

Both detectors are simple, explainable threshold rules — not a trained classifier, since there's
no labeled attack corpus to train against in most Gateway deployments. Every threshold below is
editable at runtime from the page's own config panels (saved to disk, survives redeploys) —
these are just the shipped defaults.

### Tunneling (per client + apex domain, over a 10-minute window)

| Signal | Default threshold |
|---|---|
| Minimum queries before any ratio is trusted | 30 |
| Share of queries using TXT/NULL/CNAME | ≥ 30% |
| Unique subdomains under one apex domain | ≥ 50 |
| Average full query-name length | ≥ 80 chars |
| Raw query rate to one apex domain | ≥ 100 in the window |

### DGA (per client, over a 10-minute window)

| Signal | Default threshold |
|---|---|
| Distinct domains queried before any signal is trusted | ≥ 20 |
| Minimum label length considered for entropy | ≥ 10 chars |
| Shannon entropy of a single label | ≥ 3.5 bits/char |
| NXDOMAIN ratio across those distinct domains | ≥ 80% |
| Average label entropy across those distinct domains | ≥ 3.3 bits/char |

## API

| Method | Path | What |
|---|---|---|
| `POST` | `/dns_tunneling_dga_threat_alerts/v1/ingest?token=...` | BDDS posts DNS Activity JSON here |
| `GET` | `/dns_tunneling_dga_threat_alerts/v1/ingest/health` | Unauthenticated health check for BAM's optional healthcheck |
| `GET` | `/dns_tunneling_dga_threat_alerts/v1/ingest/token` | Returns the ingest token + ready-made URL (requires an active Gateway session) |
| `GET` | `/dns_tunneling_dga_threat_alerts/v1/alerts?window=<minutes>` | Computed alerts over the given (or each detector's default) window |
| `GET`/`POST` | `/dns_tunneling_dga_threat_alerts/v1/alerts/config` | Read/update detection thresholds |
| `POST` | `/dns_tunneling_dga_threat_alerts/v1/alerts/config/reset` | Reset one or both threshold sections to defaults |
| `GET` | `/dns_tunneling_dga_threat_alerts/v1/alerts/stats` | Per-day event counts and storage size (compressed or not) |

## Testing without waiting for a real attack

`test_scripts/test_dns_tunneling.py` and `test_scripts/test_dns_dga.py` (require
`pip install dnspython`) send real DNS queries shaped like each attack pattern directly at a
target resolver, using RFC 2606 reserved domains (`.example`, `.invalid`) so they're safe to run
against a real recursive resolver without touching anything live:

```bash
python test_scripts/test_dns_tunneling.py --server <your BDDS IP>
python test_scripts/test_dns_dga.py --server <your BDDS IP>
```

## Limitations

- **Apex-domain grouping is a naive last-two-labels heuristic**, not a full public-suffix-list
  lookup — it mis-groups multi-part public suffixes (e.g. `co.uk`).
- **Thresholds are heuristic, not learned** — tune them for your traffic via the config panels;
  the shipped defaults are a reasonable starting point, not a guarantee against false
  positives/negatives.
- **High-QPS environments need capacity planning.** Storage is intentionally minimal
  (`timestamp, server, client, domain, kind, qtype/rcode`) and rolled-over days are
  gzip-compressed automatically, but at very high sustained query rates the retained window can
  still be large — size your retention (`RETENTION_DAYS` in `utils/constants.py`) accordingly.
- **Ingest auth is a single shared token**, not per-BDDS credentials — adequate for a
  trusted internal network, not a hardened multi-tenant boundary.

## License

MIT — see [LICENSE](LICENSE).
