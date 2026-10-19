import re
from datetime import datetime


# Pattern for Apache/Nginx Combined Log Format
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)


def parse_log_line(line):
    """
    Parse one Apache/Nginx combined-format log line.

    Returns a dictionary if parsing succeeds.
    Returns None if the line does not match the format.
    """

    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(
            data["timestamp"],
            "%d/%b/%Y:%H:%M:%S %z"
        )
    except ValueError:
        return None

    try:
        status = int(data["status"])
    except ValueError:
        return None

    return {
        "ip": data["ip"],
        "timestamp": timestamp.isoformat(),
        "method": data["method"],
        "path": data["path"],
        "protocol": data["protocol"],
        "status": status,
        "size": data["size"],
        "referer": data["referer"],
        "user_agent": data["user_agent"]
    }


def parse_log_file(file_path):
    """
    Read a log file one line at a time.

    This avoids loading the entire file into memory.
    """

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as file:

        for line in file:
            record = parse_log_line(line)

            if record is not None:
                yield record