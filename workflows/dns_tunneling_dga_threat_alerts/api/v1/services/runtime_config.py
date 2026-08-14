"""
Persisted, user-editable overrides for the detectors' threshold constants.

utils/constants.py's TUNNEL_*/DGA_* values are the *defaults* - what a fresh install starts
from - not hardcoded law. Any subset of them can be overridden via the DNS Tunneling/DGA Threat Alerts
page's config panels; overrides persist at `<DATA_DIR>/detector_config.json` (outside the
workflow's own code tree, same reason as the ingest token: a redeploy `rm -rf`s the code tree
but not durable data). Only fields actually saved are stored - a field left untouched keeps
tracking constants.py if that default is ever changed in a future code update.
"""
import json
import os

from ..utils import constants

CONFIG_FILE = constants.DATA_DIR + "/detector_config.json"

_RATIO_FIELDS = frozenset({"qtype_ratio_threshold", "nxdomain_ratio_threshold"})
_POSITIVE_NUMBER_FIELDS = frozenset({
    "window_minutes", "min_queries", "unique_subdomain_threshold", "query_rate_threshold",
    "min_label_len", "min_distinct_domains",
})
_NONNEGATIVE_NUMBER_FIELDS = frozenset({"avg_qlen_threshold", "entropy_threshold", "avg_entropy_threshold"})

_SCHEMA = {
    "tunneling": frozenset({
        "window_minutes", "min_queries", "suspicious_qtypes", "qtype_ratio_threshold",
        "unique_subdomain_threshold", "avg_qlen_threshold", "query_rate_threshold",
    }),
    "dga": frozenset({
        "window_minutes", "min_distinct_domains", "min_label_len", "entropy_threshold",
        "nxdomain_ratio_threshold", "avg_entropy_threshold",
    }),
}


def _defaults() -> dict:
    return {
        "tunneling": {
            "window_minutes": constants.TUNNEL_WINDOW_MINUTES,
            "min_queries": constants.TUNNEL_MIN_QUERIES,
            "suspicious_qtypes": sorted(constants.TUNNEL_SUSPICIOUS_QTYPES),
            "qtype_ratio_threshold": constants.TUNNEL_QTYPE_RATIO_THRESHOLD,
            "unique_subdomain_threshold": constants.TUNNEL_UNIQUE_SUBDOMAIN_THRESHOLD,
            "avg_qlen_threshold": constants.TUNNEL_AVG_QLEN_THRESHOLD,
            "query_rate_threshold": constants.TUNNEL_QUERY_RATE_THRESHOLD,
        },
        "dga": {
            "window_minutes": constants.DGA_WINDOW_MINUTES,
            "min_distinct_domains": constants.DGA_MIN_DISTINCT_DOMAINS,
            "min_label_len": constants.DGA_MIN_LABEL_LEN,
            "entropy_threshold": constants.DGA_ENTROPY_THRESHOLD,
            "nxdomain_ratio_threshold": constants.DGA_NXDOMAIN_RATIO_THRESHOLD,
            "avg_entropy_threshold": constants.DGA_AVG_ENTROPY_THRESHOLD,
        },
    }


def get_config() -> dict:
    """Defaults merged with whatever's been saved - a saved file only ever holds overrides."""
    merged = _defaults()
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
        except (ValueError, OSError):
            return merged
        for section, values in merged.items():
            if isinstance(saved.get(section), dict):
                values.update(saved[section])
    return merged


def _validate_field(section: str, key: str, value) -> object:
    if key not in _SCHEMA[section]:
        raise ValueError("unknown field: {}.{}".format(section, key))

    if key == "suspicious_qtypes":
        if not isinstance(value, list) or not value or not all(
            isinstance(v, str) and v.strip() for v in value
        ):
            raise ValueError("suspicious_qtypes must be a non-empty list of strings")
        return sorted({v.strip().upper() for v in value})

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("{}.{} must be a number".format(section, key))
    if key in _RATIO_FIELDS and not (0 <= value <= 1):
        raise ValueError("{}.{} must be between 0 and 1".format(section, key))
    if key in _POSITIVE_NUMBER_FIELDS and value <= 0:
        raise ValueError("{}.{} must be greater than 0".format(section, key))
    if key in _NONNEGATIVE_NUMBER_FIELDS and value < 0:
        raise ValueError("{}.{} must be 0 or greater".format(section, key))
    return value


def update_config(section: str, updates: dict) -> dict:
    if section not in _SCHEMA:
        raise ValueError("unknown section: {}".format(section))

    current = get_config()
    validated = dict(current[section])
    for key, value in updates.items():
        validated[key] = _validate_field(section, key, value)
    current[section] = validated

    os.makedirs(constants.DATA_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2)
    return current


def reset_to_defaults(section: str = None) -> dict:
    if section is None:
        if os.path.isfile(CONFIG_FILE):
            os.remove(CONFIG_FILE)
        return _defaults()

    if section not in _SCHEMA:
        raise ValueError("unknown section: {}".format(section))
    current = get_config()
    current[section] = _defaults()[section]
    os.makedirs(constants.DATA_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2)
    return current
