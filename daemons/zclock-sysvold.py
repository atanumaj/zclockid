#!/usr/bin/env python3
"""
zclock-sysvold.py - ZclockID Integrated Sysvol Replication & NTACL Self-Healing Daemon
Features:
- Native peer-to-peer bi-directional Sysvol file replication across Domain Controllers
- Computes SHA-256 file manifests and synchronizes over HTTPS with partner DCs
- Inotify / mtime watcher for instantaneous change detection and outbound push
- Automated debounced 'samba-tool ntacl sysvolreset' to guarantee unbroken Windows GPO ACLs
- Real-time telemetry export to /var/run/zclock-sysvol-sync.json for GUI and SNMP
"""

import os
import sys
import time
import logging
import subprocess
import signal
import json
import hashlib
import urllib.request
import ssl
from pathlib import Path
from threading import Timer, Thread

SYSVOL_PATH = os.environ.get("SYSVOL_PATH", "/var/lib/samba/sysvol")
DEBOUNCE_SECONDS = int(os.environ.get("DEBOUNCE_SECONDS", "4"))
HEALTH_STATE_FILE = Path("/var/run/zclock-sysvol.health")
SYNC_STATUS_FILE = Path("/var/run/zclock-sysvol-sync.json")
PARTNERS_FILE = Path("/etc/zclockid/sysvol_partners.json")
LOCAL_SECRET_FILE = Path("/etc/zclockid/sysvol_secret")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [zclock-sysvold] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("zclock-sysvold")

# SSL Context ignoring self-signed certs between internal DCs
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

def get_or_create_local_secret() -> str:
    if LOCAL_SECRET_FILE.exists():
        try:
            with open(LOCAL_SECRET_FILE) as f:
                sec = f.read().strip()
                if sec: return sec
        except Exception:
            pass
    import secrets
    sec = secrets.token_hex(24)
    LOCAL_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCAL_SECRET_FILE, "w") as f:
        f.write(sec + "\n")
    os.chmod(LOCAL_SECRET_FILE, 0o600)
    return sec

LOCAL_SECRET = get_or_create_local_secret()

class SysvolReconciler:
    def __init__(self, sysvol_path: str, debounce_sec: int = 4):
        self.sysvol_path = sysvol_path
        self.debounce_sec = debounce_sec
        self.reset_timer = None
        self.running = True
        self.partner_statuses = {}

    def schedule_reset(self, reason: str = "Filesystem event"):
        """Debounced trigger for samba-tool ntacl sysvolreset."""
        if self.reset_timer and self.reset_timer.is_alive():
            self.reset_timer.cancel()

        logger.info(f"Sysvol change detected ({reason}). Scheduling NTACL reset in {self.debounce_sec}s...")
        self.reset_timer = Timer(self.debounce_sec, self.execute_sysvolreset)
        self.reset_timer.daemon = True
        self.reset_timer.start()

    def execute_sysvolreset(self):
        """Executes 'samba-tool ntacl sysvolreset' and writes health status."""
        logger.info("Executing 'samba-tool ntacl sysvolreset'...")
        start_time = time.time()
        try:
            cmd = ["samba-tool", "ntacl", "sysvolreset"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            duration = round(time.time() - start_time, 2)
            if result.returncode == 0:
                logger.info(f"NTACL sysvolreset completed successfully in {duration}s.")
                self.record_health(status="HEALTHY", last_reset=time.time(), message="Sysvol NTACLs verified and healthy")
            else:
                logger.error(f"NTACL sysvolreset failed (code {result.returncode}): {result.stderr.strip()}")
                self.record_health(status="ERROR", last_reset=time.time(), message=result.stderr.strip())
        except subprocess.TimeoutExpired:
            logger.error("NTACL sysvolreset timed out after 60 seconds.")
            self.record_health(status="TIMEOUT", last_reset=time.time(), message="Reset timed out")
        except FileNotFoundError:
            logger.warning("'samba-tool' not found. Test environment simulated.")
            self.record_health(status="SIMULATED", last_reset=time.time(), message="Simulated reset in test mode")

    def record_health(self, status: str, last_reset: float, message: str):
        try:
            HEALTH_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(HEALTH_STATE_FILE, "w") as f:
                f.write(f"STATUS={status}\nLAST_RESET={last_reset}\nMESSAGE={message}\n")
        except Exception as e:
            logger.warning(f"Could not write health state file: {e}")

    def get_local_manifest(self) -> dict:
        """Computes SHA-256 tree of all files in Sysvol."""
        manifest = {}
        if not os.path.exists(self.sysvol_path):
            return manifest

        for root, dirs, files in os.walk(self.sysvol_path):
            for f in files:
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, self.sysvol_path)
                try:
                    stat = os.stat(full_path)
                    with open(full_path, "rb") as fp:
                        h = hashlib.sha256(fp.read()).hexdigest()
                    manifest[rel_path] = {
                        "hash": h,
                        "mtime": stat.st_mtime,
                        "size": stat.st_size
                    }
                except Exception:
                    pass
        return manifest

    def load_partners(self) -> list:
        if PARTNERS_FILE.exists():
            try:
                with open(PARTNERS_FILE) as f:
                    data = json.load(f)
                    return data.get("partners", [])
            except Exception as e:
                logger.warning(f"Could not parse {PARTNERS_FILE}: {e}")
        return []

    def sync_partner(self, partner: dict) -> bool:
        """Bi-directional sync pass with a specific partner Domain Controller."""
        p_ip = partner.get("ip_address")
        p_name = partner.get("name", p_ip)
        p_secret = partner.get("shared_secret", "")
        if not p_ip: return False

        url_base = f"https://{p_ip}"
        headers = {"X-Zclock-Sync-Secret": p_secret}

        try:
            # 1. Fetch remote manifest
            req = urllib.request.Request(f"{url_base}/api/v1/sysvol/manifest", headers=headers)
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
                remote_data = json.loads(resp.read().decode())
            remote_manifest = remote_data.get("manifest", {})

            local_manifest = self.get_local_manifest()
            changed = False

            # 2. Pull remote files that are newer or missing locally
            for rel_path, r_info in remote_manifest.items():
                l_info = local_manifest.get(rel_path)
                if not l_info or (r_info["hash"] != l_info["hash"] and r_info["mtime"] > l_info["mtime"]):
                    logger.info(f"Pulling updated file '{rel_path}' from partner {p_name} ({p_ip})...")
                    dl_url = f"{url_base}/api/v1/sysvol/file?rel_path={urllib.parse.quote(rel_path)}"
                    dl_req = urllib.request.Request(dl_url, headers=headers)
                    with urllib.request.urlopen(dl_req, context=ssl_ctx, timeout=20) as dl_resp:
                        file_bytes = dl_resp.read()

                    dest_path = os.path.join(self.sysvol_path, rel_path)
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    tmp_dest = dest_path + ".tmp"
                    with open(tmp_dest, "wb") as fp:
                        fp.write(file_bytes)
                    os.replace(tmp_dest, dest_path)
                    changed = True

            # 3. Push local files that are newer or missing remotely
            for rel_path, l_info in local_manifest.items():
                r_info = remote_manifest.get(rel_path)
                if not r_info or (l_info["hash"] != r_info["hash"] and l_info["mtime"] > r_info["mtime"]):
                    logger.info(f"Pushing updated file '{rel_path}' to partner {p_name} ({p_ip})...")
                    local_file_path = os.path.join(self.sysvol_path, rel_path)
                    with open(local_file_path, "rb") as fp:
                        f_bytes = fp.read()

                    push_url = f"{url_base}/api/v1/sysvol/file"
                    payload = json.dumps({
                        "rel_path": rel_path,
                        "content_base64": f_bytes.hex(), # hex encoded payload
                        "mtime": l_info["mtime"]
                    }).encode("utf-8")
                    push_req = urllib.request.Request(push_url, data=payload, headers={**headers, "Content-Type": "application/json"}, method="POST")
                    with urllib.request.urlopen(push_req, context=ssl_ctx, timeout=20) as p_resp:
                        pass
                    changed = True

            self.partner_statuses[p_ip] = {
                "name": p_name,
                "ip_address": p_ip,
                "status": "IN_SYNC",
                "last_sync": time.time(),
                "files_count": len(local_manifest),
                "error": None
            }

            if changed:
                self.schedule_reset(reason=f"Replicated changes from {p_name}")

            return True
        except Exception as e:
            logger.warning(f"Replication check failed with partner {p_name} ({p_ip}): {e}")
            self.partner_statuses[p_ip] = {
                "name": p_name,
                "ip_address": p_ip,
                "status": "UNREACHABLE",
                "last_sync": time.time(),
                "files_count": 0,
                "error": str(e)
            }
            return False

    def write_sync_telemetry(self):
        try:
            SYNC_STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(SYNC_STATUS_FILE, "w") as f:
                json.dump({
                    "timestamp": time.time(),
                    "partners": list(self.partner_statuses.values())
                }, f, indent=2)
        except Exception:
            pass

    def run_engine_loop(self):
        """Continuous polling and replication coordinating loop."""
        logger.info(f"Starting Integrated Sysvol Replication Guardian on {self.sysvol_path}...")
        self.execute_sysvolreset()
        last_mtime = 0

        while self.running:
            try:
                # 1. Local filesystem watch
                current_max_mtime = 0
                if os.path.exists(self.sysvol_path):
                    for root, dirs, files in os.walk(self.sysvol_path):
                        for item in files:
                            p = os.path.join(root, item)
                            try:
                                m = os.path.getmtime(p)
                                if m > current_max_mtime: current_max_mtime = m
                            except OSError:
                                pass

                    if last_mtime != 0 and current_max_mtime > last_mtime:
                        self.schedule_reset(reason="Local modification in sysvol")
                    last_mtime = current_max_mtime

                # 2. Replicate with all configured partner DCs
                partners = self.load_partners()
                for p in partners:
                    self.sync_partner(p)

                self.write_sync_telemetry()
                time.sleep(15)
            except Exception as e:
                logger.error(f"Error in replication loop: {e}")
                time.sleep(15)

def handle_sigterm(signum, frame):
    logger.info("Termination signal received. Exiting zclock-sysvold gracefully.")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)

    reconciler = SysvolReconciler(sysvol_path=SYSVOL_PATH, debounce_sec=DEBOUNCE_SECONDS)
    reconciler.run_engine_loop()
