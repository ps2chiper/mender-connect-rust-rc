"""Summarize rc UDP matrix reports into one JSON table."""
import glob
import json
import statistics
from pathlib import Path

REPORTS = Path("/mnt/c/Users/Jason Duhamell/Documents/ChatGPT/Milk V Duo/reports/mender-rust-signoff")
OUT = Path("/home/jason/releases/mender-connect-rust-0.1.0-rc.1/udp-matrix-summary.json")


def read_glob(prefix):
    rows = {}
    for path in sorted(REPORTS.glob(prefix + "-*.json")):
        try:
            d = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not d.get("trials"):
            continue
        impl = d.get("implementation")
        version = str(d.get("version"))
        case = d.get("case_filter")
        directions = {}
        for t in d["trials"]:
            for x in t.get("per_direction", []):
                directions.setdefault(x.get("direction"), []).append(x)
        summary = {
            "passed": d.get("passed"),
            "expected_seconds": d.get("expected_trial_seconds"),
            "trials": len(d["trials"]),
            "errors": d.get("harness_errors", []),
            "directions": {},
        }
        for direction, vals in directions.items():
            summary["directions"][direction] = {
                "n": len(vals),
                "median_goodput_mbps": round(statistics.median(v.get("goodput_mbps", 0) for v in vals), 3),
                "min_goodput_mbps": round(min(v.get("goodput_mbps", 0) for v in vals), 3),
                "max_goodput_mbps": round(max(v.get("goodput_mbps", 0) for v in vals), 3),
                "lost_packets": sum(v.get("lost_packets", 0) for v in vals),
                "duplicate_packets": sum(v.get("duplicate_packets", 0) for v in vals),
                "reordered_packets": sum(v.get("reordered_packets", 0) for v in vals),
            }
        rows.setdefault((version, case), {})[impl] = summary
    return rows


def render(rows):
    out = {}
    for key in sorted(rows):
        version, case = key
        entry = {}
        for impl in ("go", "rust"):
            if impl in rows[key]:
                entry[impl] = rows[key][impl]
        out[f"v{version}/{case}"] = entry
    return out


if __name__ == "__main__":
    payload = {
        "five_second": render(read_glob("rc-udp-matrix")),
        "sixty_second": render(read_glob("rc-udp-60m")),
    }
    OUT.write_text(json.dumps(payload, indent=2))
    print(json.dumps(payload, indent=2))