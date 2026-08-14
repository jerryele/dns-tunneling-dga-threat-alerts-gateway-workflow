"""
Day-bucketed JSONL storage for filtered DNS activity records, with a rolling retention purge
and gzip compression of rolled-over (non-today) day files.

Mirrors BDDS's own namedmon/perfstats convention (one file per UTC calendar day) rather than
inventing a new layout - makes the retention purge a simple filename-age check, no database.
Only the current day's file is ever appended to, in plain text (gzip doesn't support cheap
incremental appends). Once a day rolls over it's never written to again, so it's compressed
the next time append_records() runs - no separate scheduled job needed, since ingest traffic
itself drives this frequently enough.
"""
import glob
import gzip
import json
import os
import shutil
import threading
from datetime import datetime, timedelta, timezone

from ..utils.constants import EVENTS_DIR, RETENTION_DAYS

_write_lock = threading.Lock()


def _day_str(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d")


def _file_for_day(day_str: str) -> str:
    return os.path.join(EVENTS_DIR, "events-{}.jsonl".format(day_str))


def _day_str_from_filename(name: str) -> str:
    if name.endswith(".jsonl.gz"):
        return name[len("events-"):-len(".jsonl.gz")]
    if name.endswith(".jsonl"):
        return name[len("events-"):-len(".jsonl")]
    return ""


def _day_files() -> dict:
    """
    Map day_str -> path, one entry per day. If both a plain and compressed file exist for the
    same day (a narrow crash window inside _compress_old_days, between the gzip write and the
    plain-file removal), the compressed one wins - its existence means the gzip write already
    completed successfully, so it's the one to trust.
    """
    files = {}
    if not os.path.isdir(EVENTS_DIR):
        return files
    for path in glob.glob(os.path.join(EVENTS_DIR, "events-*.jsonl")):
        day_str = _day_str_from_filename(os.path.basename(path))
        if len(day_str) == 8 and day_str.isdigit():
            files.setdefault(day_str, path)
    for path in glob.glob(os.path.join(EVENTS_DIR, "events-*.jsonl.gz")):
        day_str = _day_str_from_filename(os.path.basename(path))
        if len(day_str) == 8 and day_str.isdigit():
            files[day_str] = path
    return files


def _open_day_file(path: str):
    return gzip.open(path, "rt", encoding="utf-8") if path.endswith(".gz") else open(path, "r", encoding="utf-8")


def append_records(records: list) -> None:
    if not records:
        return
    by_day = {}
    for r in records:
        by_day.setdefault(_day_str(r["ts"]), []).append(r)

    os.makedirs(EVENTS_DIR, exist_ok=True)
    with _write_lock:
        for day_str, day_records in by_day.items():
            with open(_file_for_day(day_str), "a", encoding="utf-8") as f:
                for r in day_records:
                    f.write(json.dumps(r, separators=(",", ":")))
                    f.write("\n")
    _compress_old_days()
    purge_old()


def _compress_old_days() -> None:
    """
    Gzip every plain-text day file that isn't today's. Writes to a `.tmp` path first and
    `os.replace`s it into place before removing the source - so a crash mid-compress leaves at
    worst a stray `.tmp` file (cleaned up by being overwritten next pass), never a half-written
    `.gz` masquerading as done.
    """
    if not os.path.isdir(EVENTS_DIR):
        return
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    with _write_lock:
        for path in glob.glob(os.path.join(EVENTS_DIR, "events-*.jsonl")):
            day_str = _day_str_from_filename(os.path.basename(path))
            if not (len(day_str) == 8 and day_str.isdigit()) or day_str == today:
                continue
            gz_path = path + ".gz"
            tmp_path = gz_path + ".tmp"
            try:
                with open(path, "rb") as src, gzip.open(tmp_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                os.replace(tmp_path, gz_path)
                os.remove(path)
            except OSError:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass


def purge_old() -> list:
    """Delete any day-file (compressed or not) older than RETENTION_DAYS. Returns the list of
    files removed."""
    cutoff_day = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).strftime("%Y%m%d")
    removed = []
    for day_str, path in _day_files().items():
        if day_str < cutoff_day:
            try:
                os.remove(path)
                removed.append(os.path.basename(path))
            except OSError:
                pass
    return removed


def read_window(start_ts: float, end_ts: float):
    """Yield every stored record with start_ts <= ts <= end_ts, oldest day first."""
    start_day = _day_str(start_ts)
    end_day = _day_str(end_ts)
    day_files = _day_files()
    for day_str in sorted(day_files):
        if day_str < start_day or day_str > end_day:
            continue
        try:
            with _open_day_file(day_files[day_str]) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if start_ts <= record.get("ts", 0) <= end_ts:
                        yield record
        except OSError:
            continue


def storage_stats() -> dict:
    day_files = _day_files()
    days = []
    total_events = 0
    total_bytes = 0
    for day_str in sorted(day_files):
        path = day_files[day_str]
        try:
            with _open_day_file(path) as f:
                count = sum(1 for _ in f)
            size_bytes = os.path.getsize(path)
        except OSError:
            count, size_bytes = 0, 0
        days.append({
            "day": day_str, "events": count, "bytes": size_bytes,
            "compressed": path.endswith(".gz"),
        })
        total_events += count
        total_bytes += size_bytes
    return {"days": days, "total_events": total_events, "total_bytes": total_bytes}
