"""Format parsers for TXT, CSV, and JSON threat feeds."""

import csv
import io
import json
import logging
from typing import List
from src.models import RawCandidate

logger = logging.getLogger("ti_aggregator.parsers")

COMMON_INDICATOR_KEYS = {
    "ip", "ip_address", "host", "domain", "url", "hash", "md5",
    "sha1", "sha256", "indicator", "value", "ioc", "email", "sender"
}

CONTEXT_KEYS = {"malware", "threat", "tags", "notes", "reporter", "description", "status"}


def parse_raw_feed(content: str, feed_format: str, feed_id: str) -> List[RawCandidate]:
    """Parses raw feed text into a list of RawCandidate objects."""
    if not content:
        return []

    format_lower = feed_format.lower().strip()
    if format_lower == "json":
        return _parse_json(content, feed_id)
    elif format_lower == "csv":
        return _parse_csv(content, feed_id)
    else:
        return _parse_txt(content, feed_id)


def _parse_txt(content: str, feed_id: str) -> List[RawCandidate]:
    candidates = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
            continue
        # If line contains whitespace or delimiters (e.g. "1.2.3.4  # bad bot"), grab first token
        tokens = line.split()
        if tokens:
            candidate_val = tokens[0].strip(",")
            context_val = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            candidates.append(RawCandidate(raw_value=candidate_val, feed_id=feed_id, context=context_val))
    return candidates


def _parse_csv(content: str, feed_id: str) -> List[RawCandidate]:
    candidates = []
    # Skip comment lines at the start of CSV (common in URLhaus / Abuse.ch feeds)
    clean_lines = [line for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
    if not clean_lines:
        return []

    f = io.StringIO("\n".join(clean_lines))
    reader = csv.DictReader(f)

    if reader.fieldnames:
        fieldnames_lower = {name.lower().strip(): name for name in reader.fieldnames if name}
        # Find matching indicator column
        indicator_col = None
        for key in COMMON_INDICATOR_KEYS:
            if key in fieldnames_lower:
                indicator_col = fieldnames_lower[key]
                break

        for row in reader:
            if indicator_col and row.get(indicator_col):
                val = row[indicator_col].strip()
                # Gather contexts
                contexts = []
                for ck in CONTEXT_KEYS:
                    if ck in fieldnames_lower and row.get(fieldnames_lower[ck]):
                        contexts.append(f"{ck}:{row[fieldnames_lower[ck]].strip()}")
                ctx_str = ", ".join(contexts)
                candidates.append(RawCandidate(raw_value=val, feed_id=feed_id, context=ctx_str))
            else:
                # Fallback: scan all cells in the row
                for col_name, cell in row.items():
                    if cell and isinstance(cell, str) and len(cell.strip()) > 3:
                        candidates.append(RawCandidate(raw_value=cell.strip(), feed_id=feed_id, context=f"col:{col_name}"))
    else:
        # Standard unheadered CSV
        f.seek(0)
        raw_reader = csv.reader(f)
        for row in raw_reader:
            for cell in row:
                if cell and len(cell.strip()) > 3:
                    candidates.append(RawCandidate(raw_value=cell.strip(), feed_id=feed_id))

    return candidates


def _parse_json(content: str, feed_id: str) -> List[RawCandidate]:
    candidates = []
    try:
        data = json.loads(content)
    except Exception as e:
        logger.error("Failed to parse JSON for feed %s: %s", feed_id, e)
        return []

    if isinstance(data, list):
        for item in data:
            _extract_from_json_item(item, feed_id, candidates)
    elif isinstance(data, dict):
        # Could be { "iocs": [...] } or dictionary of indicators
        for k, v in data.items():
            if isinstance(v, list):
                for item in v:
                    _extract_from_json_item(item, feed_id, candidates)
            else:
                _extract_from_json_item(data, feed_id, candidates)
                break
    return candidates


def _extract_from_json_item(item: any, feed_id: str, out_list: List[RawCandidate]):
    if isinstance(item, str):
        out_list.append(RawCandidate(raw_value=item.strip(), feed_id=feed_id))
        return

    if not isinstance(item, dict):
        return

    # Check for primary indicator keys
    found_val = None
    item_lower = {k.lower(): v for k, v in item.items()}
    for key in COMMON_INDICATOR_KEYS:
        if key in item_lower and isinstance(item_lower[key], (str, int)):
            found_val = str(item_lower[key]).strip()
            break

    if found_val:
        # Collect contextual metadata
        contexts = []
        for ck in CONTEXT_KEYS:
            if ck in item_lower and item_lower[ck]:
                contexts.append(f"{ck}:{item_lower[ck]}")
        ctx_str = ", ".join(contexts)
        out_list.append(RawCandidate(raw_value=found_val, feed_id=feed_id, context=ctx_str))
    else:
        # Fallback: inspect any string values
        for k, v in item.items():
            if isinstance(v, str) and len(v.strip()) > 3:
                out_list.append(RawCandidate(raw_value=v.strip(), feed_id=feed_id, context=f"key:{k}"))
