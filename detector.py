import json
import re
from pathlib import Path
from urllib.parse import unquote_plus


BASE_DIR = Path(__file__).resolve().parent
SIGNATURES_FILE = BASE_DIR / "signatures.json"


def load_signatures():
    """Load attack signatures from the JSON file."""

    with SIGNATURES_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def detect_attacks(record, signatures=None):
    """Detect suspicious patterns in a parsed log record."""

    if signatures is None:
        signatures = load_signatures()

    method = record.get("method", "")
    path = record.get("path", "")

    # Check both the original and URL-decoded request.
    decoded_path = unquote_plus(path)

    request_variants = [
        f"{method} {path}",
        f"{method} {decoded_path}"
    ]

    findings = []

    for attack_type, details in signatures.items():
        for pattern in details["patterns"]:

            matched = any(
                re.search(pattern, request, re.IGNORECASE)
                for request in request_variants
            )

            if matched:
                findings.append({
                    "type": attack_type,
                    "severity": details["severity"],
                    "description": details["description"],
                    "matched_pattern": pattern
                })

                break

    return findings