import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

RUNNER = Path("/mnt/c/Users/Jason Duhamell/Documents/ChatGPT/Milk V Duo/trial-tools/run_udp_paced_sweep.py")
PEER = Path("/mnt/c/Users/Jason Duhamell/Documents/ChatGPT/Milk V Duo/trial-tools/udp-acceptance-review")
BIN = Path("/home/jason/releases/mender-connect-rust-0.1.0-rc.1/target/release/mender-connect-rust")
SHA = "21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4"

ap = argparse.ArgumentParser()
ap.add_argument("--repeats", type=int, default=10)
ap.add_argument("--version", default="1")
ap.add_argument("--case", default="4096/full_duplex")
ap.add_argument("--rate", default="65.536")
ap.add_argument("--prefix", default="rc-udp-4096-rep")
ap.add_argument("--implementation", choices=["rust", "go"], default="rust")
ap.add_argument("--binary", default=str(BIN))
ap.add_argument("--sha", default=SHA)
ap.add_argument("--status", required=True)
args = ap.parse_args()
BIN = Path(args.binary)
SHA = args.sha

status = {"started": time.time(), "repeats": args.repeats, "runs": []}
Path(args.status).write_text(json.dumps(status, indent=2))
for i in range(1, args.repeats + 1):
    report = f"{args.prefix}-{i:02d}.json"
    cmd = [
        sys.executable, str(RUNNER),
        "--version", args.version,
        "--case", args.case,
        "--fixed-rate-mbps", args.rate,
        "--implementation", args.implementation,
        "--binary", str(BIN),
        "--expected-sha256", SHA,
        "--trial-seconds", "60",
        "--trial-count", "3",
        "--peer-source", str(PEER),
        "--report", report,
    ]
    started = time.time()
    result = subprocess.run(cmd, cwd=str(RUNNER.parent.parent), timeout=900)
    entry = {"repeat": i, "report": report, "exit": result.returncode,
             "elapsed_seconds": round(time.time() - started, 2)}
    status["runs"].append(entry)
    Path(args.status).write_text(json.dumps(status, indent=2))
    print("RUN", entry, flush=True)
print("DONE", json.dumps(status, indent=2), flush=True)