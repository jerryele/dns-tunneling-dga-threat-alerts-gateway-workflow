"""
Turns a raw HTTP body from BDDS's "HTTP" DNS Activity destination into compact records.

BAM's generic HTTP destination (as opposed to its separate "Splunk HEC" destination type)
POSTs the dnstap-derived JSON events themselves, batched by size/age - not wrapped in any
HEC-style envelope. A batch is not guaranteed to be a single JSON document (could be
newline-delimited objects, concatenated with no separator, or a JSON array), so this parses
the raw text as a stream of JSON values rather than calling `json.loads()` once.

Real sample event shape (dnstap-derived JSON, same schema BAM's generic HTTP destination
carries for both DNS Activity destination types):

    {
      "messageType": "ClientQuery", "sourceAddress": "10.0.0.5", "serverId": "bdds251a",
      "time": 1785504679305901174, "timePrecision": "ns",
      "requestData": {"question": [{"domainName": "www.example.com.", "questionType": "A"}], ...}
    }
    {
      "messageType": "ClientResponse", "sourceAddress": "10.0.0.5", "serverId": "bdds251a",
      "time": 1785504679306001174,
      "requestData": {"time": 1785504679285901174},
      "responseData": {"question": [{"domainName": "www.example.com."}], "rcodeName": "NoError",
                        "header": {"anCount": 1}}
    }
"""
import json
import math
from typing import Iterator, Optional

from ..utils.constants import ALLOWED_MESSAGE_TYPES


def iter_json_objects(raw_text: str) -> Iterator[dict]:
    """
    Yield every top-level JSON value found in `raw_text`, regardless of whether they're
    separated by newlines, back-to-back with no separator, or wrapped in a single array.
    Malformed trailing content is silently stopped at, not raised - a partial/corrupt batch
    shouldn't lose the events that parsed fine before it.
    """
    decoder = json.JSONDecoder()
    idx = 0
    n = len(raw_text)
    while idx < n:
        while idx < n and raw_text[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        try:
            obj, end = decoder.raw_decode(raw_text, idx)
        except ValueError:
            break
        idx = end
        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    yield item
        elif isinstance(obj, dict):
            yield obj


def shannon_entropy(s: str) -> float:
    """Bits per character. Empty/single-char strings have 0 entropy by definition."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def apex_domain(domain: str) -> str:
    """
    Naive eTLD+1 approximation: last two labels. Doesn't handle multi-part public suffixes
    (e.g. "co.uk") correctly - a deliberate v1 simplification rather than shipping/maintaining
    a full public-suffix-list dependency. Good enough for grouping queries by "which domain is
    this subdomain activity actually targeting" in the common single-part-TLD case.
    """
    labels = [l for l in domain.rstrip(".").split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def leftmost_label(domain: str) -> str:
    labels = [l for l in domain.rstrip(".").split(".") if l]
    return labels[0] if labels else ""


def extract_record(event: dict) -> Optional[dict]:
    """
    Reduce one raw dnstap event down to the minimum fields detection actually needs to store,
    or return None if this event isn't one we keep (wrong messageType, or missing a required
    field). `apex`/`qlen`/`label_len`/`label_entropy` are all cheap, pure functions of `domain`
    - rather than storing them (they were, in an earlier version, and roughly doubled
    per-record size for values detector.py can just as easily compute at read time), the
    detector recomputes them itself, once per distinct domain in whatever window it's
    scanning. `an_count` was dropped outright - captured originally as "might be useful for
    NODATA detection" but never actually consumed by either detector.
    """
    message_type = event.get("messageType")
    if message_type not in ALLOWED_MESSAGE_TYPES:
        return None

    time_ns = event.get("time")
    if not isinstance(time_ns, (int, float)):
        return None

    kind = "query" if message_type == "ClientQuery" else "response"
    side = event.get("requestData") if kind == "query" else event.get("responseData")
    if not isinstance(side, dict):
        return None

    questions = side.get("question")
    if not isinstance(questions, list) or not questions:
        return None
    question = questions[0]
    domain = question.get("domainName")
    if not domain:
        return None
    domain = domain.rstrip(".").lower()

    record = {
        "ts": time_ns / 1e9,
        "server": event.get("serverId"),
        "client": event.get("sourceAddress"),
        "kind": kind,
        "domain": domain,
    }
    if kind == "query":
        record["qtype"] = question.get("questionType")
    else:
        record["rcode"] = event.get("responseData", {}).get("rcodeName")
    return record
