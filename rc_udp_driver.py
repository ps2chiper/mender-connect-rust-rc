import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

RUNNER = Path("/mnt/c/Users/Jason Duhamell/Documents/ChatGPT/Milk V Duo/trial-tools/run_udp_paced_sweep.py")
GO_BIN = Path("/home/jason/.local/share/duo-aider/mender-rust-trial/go-original-matched-daemon")
GO_SHA = "364fc12f9e11cb99ed3c9ab51ca8d996299f20176518af17404e9c0f0230c3ce"
RUST_BIN = Path("/home/jason/releases/mender-connect-rust-0.1.0-rc.1/target/release/mender-connect-rust")
RUST_SHA = "21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4"

RATES = {
    ("1", "1400/to_device"): 33.6,
    ("1", "1400/from_device"): 22.4,
    ("1", "1400/full_duplex"): 33.6,
    ("1", "4096/to_device"): 98.304,
    ("1", "4096/from_device"): 32.768,
    ("1", "4096/full_duplex"): 65.536,
    ("2", "1400/to_device"): 179.2,
    ("2", "1400/from_device"): 89.6,
    ("2", "1400/full_duplex"): 89.6,
    ("2", "4096/to_device"): 262.144,
    ("2", "4096/from_device"): 65.536,
    ("2", "4096/full_duplex"): 65.536,
}

ap = argparse.ArgumentParser()
ap.add_argument("--seconds", type=int, default=5)
ap.add_argument("--trials", type=int, default=3)
ap.add_argument("--prefix", default="rc-udp-matrix")
ap.add_argument("--peer-source", default="")
ap.add_argument("--rust-binary", default="")
ap.add_argument("--rust-sha", default="")
ap.add_argument("--implementations", default="go,rust")
ap.add_argument("--versions", default="1,2")
ap.add_argument("--cases", default="1400/to_device,1400/from_device,1400/full_duplex,4096/to_device,4096/from_device,4096/full_duplex")
ap.add_argument("--status", required=True)
args = ap.parse_args()

if args.rust_binary:
    RUST_BIN = Path(args.rust_binary)
if args.rust_sha:
    RUST_SHA = args.rust_sha

status = {"started": time.time(), "seconds": args.seconds, "trials": args.trials, "runs": []}
Path(args.status).write_text(json.dumps(status, indent=2))

for version in args.versions.split(","):
    for case in args.cases.split(","):
        rate = RATES[(version, case)]
        for impl in args.implementations.split(","):
            bin_path, bin_sha = (GO_BIN, GO_SHA) if impl == "go" else (RUST_BIN, RUST_SHA)
            report = f"{args.prefix}-{impl}-v{version}-{case.replace('/', '-')}.json"
            cmd = [
                sys.executable, str(RUNNER),
                "--version", version,
                "--case", case,
                "--fixed-rate-mbps", str(rate),
                "--implementation", impl,
                "--binary", str(bin_path),
                "--expected-sha256", bin_sha,
                "--trial-seconds", str(args.seconds),
                "--trial-count", str(args.trials),
                "--report", report,
            ]
            if args.peer_source:
                cmd += ["--peer-source", args.peer_source]
            started = time.time()
            result = subprocess.run(cmd, cwd=str(RUNNER.parent.parent), timeout=900)
            entry = {
                "version": version, "case": case, "rate": rate, "implementation": impl,
                "report": report, "exit": result.returncode,
                "elapsed_seconds": round(time.time() - started, 2),
            }
            status["runs"].append(entry)
            Path(args.status).write_text(json.dumps(status, indent=2))
            print("RUN", entry, flush=True)
print("DONE", json.dumps(status, indent=2), flush=True)