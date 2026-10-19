from flask import Flask, render_template, request
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from tempfile import NamedTemporaryFile

from parser import parse_log_line
from detector import detect_attacks, load_signatures


app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {".log", ".txt"}

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


# ==========================================
# BRUTE-FORCE DETECTION
# ==========================================

def detect_brute_force(records, threshold=5, window_seconds=60):
    """
    Flag potential brute-force activity when one IP address
    generates at least five HTTP 401 responses on authentication
    endpoints within a 60-second window.
    """

    failed_logins = defaultdict(list)

    for record in records:
        if record.get("status") != 401:
            continue

        path = record.get("path", "").lower()

        if not any(
            endpoint in path
            for endpoint in ("/login", "/signin", "/auth")
        ):
            continue

        try:
            timestamp = datetime.fromisoformat(record["timestamp"])
        except (ValueError, TypeError, KeyError):
            continue

        failed_logins[record["ip"]].append(timestamp)

    alerts = []

    for ip, timestamps in failed_logins.items():
        timestamps.sort()

        left = 0

        for right, current_time in enumerate(timestamps):
            while (
                current_time - timestamps[left]
            ).total_seconds() > window_seconds:
                left += 1

            attempts = right - left + 1

            if attempts >= threshold:
                alerts.append({
                    "ip": ip,
                    "attempts": attempts,
                    "window_seconds": window_seconds,
                    "type": "brute_force",
                    "severity": "high",
                    "description": (
                        f"{attempts} failed authentication responses "
                        f"within {window_seconds} seconds"
                    ),
                    "timestamp": current_time.isoformat()
                })

                # One alert per IP address.
                break

    return alerts


# ==========================================
# LOG ANALYSIS
# ==========================================

def analyze_lines(lines):
    signatures = load_signatures()
    """Parse log lines and identify suspicious requests."""

    total_lines = 0
    parsed_records = 0
    invalid_lines = 0

    records = []
    findings = []

    attack_counts = Counter()
    ip_counts = Counter()

    # Parse each log line and detect individual attacks.
    for line in lines:
        total_lines += 1

        record = parse_log_line(line)

        if record is None:
            invalid_lines += 1
            continue

        parsed_records += 1
        records.append(record)

        record_findings = detect_attacks(record, signatures)

        for finding in record_findings:
            attack_counts[finding["type"]] += 1
            ip_counts[record["ip"]] += 1

            findings.append({
                "ip": record["ip"],
                "timestamp": record["timestamp"],
                "method": record["method"],
                "path": record["path"],
                "status": record["status"],
                "type": finding["type"],
                "severity": finding["severity"],
                "description": finding["description"]
            })

    # Detect repeated failed authentication attempts.
    brute_force_alerts = detect_brute_force(records)

    for alert in brute_force_alerts:
        attack_counts[alert["type"]] += 1
        ip_counts[alert["ip"]] += 1

        findings.append({
            "ip": alert["ip"],
            "timestamp": alert["timestamp"],
            "method": "POST",
            "path": "/login",
            "status": 401,
            "type": alert["type"],
            "severity": alert["severity"],
            "description": alert["description"]
        })
    # Count findings per hour for the timeline chart.
    hourly_counts = Counter()

    for finding in findings:
        hour = finding["timestamp"][:13]
        hourly_counts[hour] += 1

    hourly_labels = [
        hour.replace("T", " ") + ":00"
        for hour in sorted(hourly_counts)
    ]
    hourly_values = [
        hourly_counts[hour] for hour in sorted(hourly_counts)
    ]
    # Return the complete analysis report.
    return {
        "total_lines": total_lines,
        "parsed_records": parsed_records,
        "invalid_lines": invalid_lines,
        "total_findings": len(findings),
        "attack_counts": dict(attack_counts),
        "top_ips": ip_counts.most_common(10),
        "findings": findings,
        "hourly_labels": hourly_labels,
        "hourly_values": hourly_values
    }


# ==========================================
# FILE ANALYSIS
# ==========================================

def analyze_file(file_path):
    """Read and analyze a log file."""

    def read_lines():
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:
            yield from file

    return analyze_lines(read_lines())


# ==========================================
# MAIN DASHBOARD
# ==========================================

@app.route("/", methods=["GET", "POST"])
def home():

    report = None
    error = None

    if request.method == "POST":

        uploaded_file = request.files.get("logfile")

        if not uploaded_file or not uploaded_file.filename:
            error = "Please select a log file."

        elif Path(
            secure_filename(uploaded_file.filename)
        ).suffix.lower() not in ALLOWED_EXTENSIONS:

            error = "Please upload a .log or .txt file."

        else:
            try:
                with NamedTemporaryFile(mode="wb+") as temporary_file:

                    total_bytes = 0

                    while True:
                        chunk = uploaded_file.stream.read(64 * 1024)

                        if not chunk:
                            break

                        total_bytes += len(chunk)

                        if total_bytes > MAX_FILE_SIZE:
                            raise ValueError(
                                "The uploaded file exceeds 10 MB."
                            )

                        temporary_file.write(chunk)

                    temporary_file.flush()

                    report = analyze_file(temporary_file.name)
                    report["filename"] = secure_filename(uploaded_file.filename)

            except ValueError as exc:
                error = str(exc)

    return render_template(
        "index.html",
        report=report,
        error=error
    )


# ==========================================
# DEMO LOG
# ==========================================

@app.route("/demo", methods=["POST"])
def demo():

    demo_file = BASE_DIR / "samle_logs" / "demo.log"

    if not demo_file.is_file():
        return "Demo log file was not found.", 404

    report = analyze_file(demo_file)
    report["filename"] = demo_file.name

    return render_template(
        "index.html",
        report=report,
        error=None
    )


# ==========================================
# FILE SIZE ERROR
# ==========================================

@app.errorhandler(413)
def file_too_large(error):

    return "File too large. The current limit is 10 MB.", 413


# ==========================================
# START APPLICATION
# ==========================================

if __name__ == "__main__":
    app.run(port=5000)