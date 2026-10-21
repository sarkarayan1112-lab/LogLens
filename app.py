import json
import os
import threading
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from tempfile import gettempdir, mkstemp

from flask import Flask, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from parser import parse_log_line
from detector import detect_attacks, load_signatures
from geo import build_geo


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
    """Parse log lines and identify suspicious requests."""

    signatures = load_signatures()

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

    # Find where the attacking IP addresses are located (GeoIP).
    geo = build_geo(ip_counts)

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
        "hourly_values": hourly_values,
        "geo_points": geo["points"],
        "country_counts": geo["country_counts"],
        "geo_unlocated": geo["unlocated"]
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
# BACKGROUND JOBS (JOB ID + STATUS)
# ==========================================
#
# Flow:  Upload  ->  get a Job ID  ->  poll the status  ->  view the report
#
# The analysis runs in a background thread, so the web page answers
# immediately. Each job is saved as a small JSON file in a temporary
# folder. Because the state lives in files (not in one worker's memory),
# it works even if the server runs more than one worker process.

JOBS_DIR = Path(gettempdir()) / "loglens_jobs"
JOBS_DIR.mkdir(parents=True, exist_ok=True)

JOB_MAX_AGE_SECONDS = 60 * 60  # old jobs are deleted after one hour


def is_valid_job_id(job_id):
    """Job IDs are 32 hexadecimal characters (blocks path tricks)."""
    return (
        len(job_id) == 32
        and all(char in "0123456789abcdef" for char in job_id)
    )


def job_file(job_id):
    return JOBS_DIR / f"{job_id}.json"


def save_job(job):
    """Write a job file safely (write a temp file, then swap it in)."""
    target = job_file(job["id"])
    temp = target.with_suffix(".tmp")

    with open(temp, "w", encoding="utf-8") as file:
        json.dump(job, file)

    os.replace(temp, target)


def load_job(job_id):
    """Return the job dictionary, or None if it does not exist."""
    if not is_valid_job_id(job_id):
        return None

    try:
        with open(job_file(job_id), "r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def cleanup_old_jobs():
    """Delete job files older than JOB_MAX_AGE_SECONDS."""
    cutoff = time.time() - JOB_MAX_AGE_SECONDS

    for path in JOBS_DIR.glob("*.json"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            pass


def run_job(job_id, file_path, filename, delete_when_done):
    """Runs in a background thread: analyze the file and save the result."""

    job = load_job(job_id) or {
        "id": job_id,
        "filename": filename,
        "created": time.time()
    }

    job["status"] = "processing"
    save_job(job)

    try:
        report = analyze_file(file_path)
        report["filename"] = filename

        job["report"] = report
        job["status"] = "done"

    except Exception:
        job["status"] = "failed"
        job["error"] = "The log file could not be analyzed."

    finally:
        job["finished"] = time.time()
        save_job(job)

        if delete_when_done:
            try:
                os.remove(file_path)
            except OSError:
                pass


def start_job(file_path, filename, delete_when_done):
    """Create a job, start it in the background, return its Job ID."""

    cleanup_old_jobs()

    job_id = uuid.uuid4().hex

    save_job({
        "id": job_id,
        "filename": filename,
        "status": "queued",
        "created": time.time()
    })

    worker = threading.Thread(
        target=run_job,
        args=(job_id, file_path, filename, delete_when_done),
        daemon=True
    )
    worker.start()

    return job_id


# ==========================================
# MAIN DASHBOARD (UPLOAD)
# ==========================================

@app.route("/", methods=["GET", "POST"])
def home():

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
            # Stream the upload to a temporary file in 64 KB chunks.
            file_descriptor, temp_path = mkstemp(suffix=".log")

            try:
                total_bytes = 0

                with os.fdopen(file_descriptor, "wb") as temporary_file:
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

            except ValueError as exc:
                error = str(exc)

                try:
                    os.remove(temp_path)
                except OSError:
                    pass

            else:
                job_id = start_job(
                    temp_path,
                    secure_filename(uploaded_file.filename),
                    delete_when_done=True
                )

                return redirect(url_for("report_page", job_id=job_id))

    return render_template(
        "index.html",
        report=None,
        job=None,
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

    job_id = start_job(
        str(demo_file),
        demo_file.name,
        delete_when_done=False
    )

    return redirect(url_for("report_page", job_id=job_id))


# ==========================================
# JOB STATUS AND REPORT
# ==========================================

@app.route("/status/<job_id>")
def job_status(job_id):
    """Small JSON answer used by the page to poll the job."""

    job = load_job(job_id)

    if job is None:
        return jsonify({"error": "Job not found"}), 404

    return jsonify({
        "job_id": job["id"],
        "status": job["status"],
        "error": job.get("error")
    })


@app.route("/report/<job_id>")
def report_page(job_id):
    """Show the waiting screen, or the finished report."""

    job = load_job(job_id)

    if job is None:
        return render_template(
            "index.html",
            report=None,
            job=None,
            error="This job was not found. It may have expired. "
                  "Please upload the file again."
        ), 404

    report = job.get("report") if job["status"] == "done" else None

    return render_template(
        "index.html",
        report=report,
        job=job,
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
