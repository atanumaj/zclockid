"""
ZclockID NTP Management Router
Authoritative Windows Time / MS-SNTP / Chrony Service integration
"""

import csv
import io
from fastapi import APIRouter, HTTPException, Depends
from api.core.config import (
    CHRONY_CONF_DIR,
    CHRONY_SOURCES_DIR,
    ZCLOCK_NTP_CONF,
    ZCLOCK_NTP_SOURCES,
)
from api.services.system_service import run_cmd, log_audit
from api.schemas.ntp_schema import NtpConfigRequest

router = APIRouter(prefix="/api/v1/ntp", tags=["NTP Time Service"])

@router.get("/status")
def get_ntp_status():
    code_td, out_td, _ = run_cmd(["timedatectl"])
    local_time = "-"
    utc_time = "-"
    tz_str = "UTC"
    clock_synced = False
    ntp_active = False

    if code_td == 0:
        for line in out_td.splitlines():
            if "Local time:" in line:
                local_time = line.split(":", 1)[1].strip()
            elif "Universal time:" in line:
                utc_time = line.split(":", 1)[1].strip()
            elif "Time zone:" in line:
                tz_str = line.split(":", 1)[1].strip()
            elif "System clock synchronized:" in line:
                clock_synced = "yes" in line.lower()
            elif "NTP service:" in line:
                ntp_active = "active" in line.lower()

    code_tr, out_tr, _ = run_cmd(["chronyc", "tracking"])
    tracking = {}
    if code_tr == 0:
        for line in out_tr.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                tracking[k.strip()] = v.strip()

    sources = []
    code_src, out_src, _ = run_cmd(["chronyc", "-c", "sources"])
    if code_src == 0:
        reader = csv.reader(io.StringIO(out_src.strip()))
        for row in reader:
            if len(row) >= 10:
                m_c, s_c, addr, strat, poll, reach, rx, sample, orig, err = row[:10]
                sources.append({
                    "mode": "Server" if m_c == "^" else ("Peer" if m_c == "=" else "Local"),
                    "state": "Active (Best)" if s_c == "*" else ("Combined" if s_c == "+" else ("Candidate" if s_c == "-" else s_c)),
                    "address": addr,
                    "stratum": int(strat) if strat.isdigit() else strat,
                    "poll": poll,
                    "reach": reach,
                    "last_rx": f"{rx}s ago",
                    "offset": sample,
                    "est_error": err
                })

    code_ss, out_ss, _ = run_cmd(["ss", "-ulpn"])
    is_server_listening = (code_ss == 0 and ":123 " in out_ss and "chronyd" in out_ss)

    return {
        "service_active": ntp_active,
        "server_listening": is_server_listening,
        "clock_synchronized": clock_synced,
        "local_time": local_time,
        "utc_time": utc_time,
        "timezone": tz_str,
        "stratum": int(tracking.get("Stratum", 0)) if str(tracking.get("Stratum", "0")).isdigit() else 0,
        "reference_id": tracking.get("Reference ID", "-"),
        "system_time_offset": tracking.get("System time", "-"),
        "last_offset": tracking.get("Last offset", "-"),
        "rms_offset": tracking.get("RMS offset", "-"),
        "leap_status": tracking.get("Leap status", "Normal"),
        "sources": sources
    }

@router.get("/config")
def get_ntp_config():
    ntp_server_enabled = True
    allowed_subnets = "0.0.0.0/0, ::/0"
    ms_sntp_enabled = True
    upstream_servers = ["time.google.com", "pool.ntp.org", "time.windows.com"]

    if ZCLOCK_NTP_CONF.exists():
        try:
            with open(ZCLOCK_NTP_CONF) as f:
                text = f.read()
                ms_sntp_enabled = "ntpsigndsocket" in text
                allows = []
                for line in text.splitlines():
                    if line.strip().startswith("allow"):
                        parts = line.strip().split()
                        if len(parts) > 1:
                            allows.append(parts[1])
                if allows:
                    allowed_subnets = ", ".join(allows)
                ntp_server_enabled = len(allows) > 0
        except Exception:
            pass

    if ZCLOCK_NTP_SOURCES.exists():
        try:
            with open(ZCLOCK_NTP_SOURCES) as f:
                pools = []
                for line in f.splitlines():
                    line = line.strip()
                    if line.startswith("pool") or line.startswith("server"):
                        parts = line.split()
                        if len(parts) > 1:
                            pools.append(parts[1])
                if pools:
                    upstream_servers = pools
        except Exception:
            pass

    code_tz, out_tz, _ = run_cmd(["timedatectl", "show", "--property=Timezone", "--value"])
    current_tz = out_tz.strip() if code_tz == 0 and out_tz.strip() else "UTC"

    available_timezones = [
        "Asia/Kolkata", "UTC", "America/New_York", "America/Chicago",
        "America/Denver", "America/Los_Angeles", "Europe/London",
        "Europe/Paris", "Europe/Berlin", "Asia/Dubai", "Asia/Singapore",
        "Asia/Tokyo", "Australia/Sydney"
    ]

    return {
        "ntp_server_enabled": ntp_server_enabled,
        "allowed_subnets": allowed_subnets,
        "ms_sntp_enabled": ms_sntp_enabled,
        "upstream_servers": upstream_servers,
        "timezone": current_tz,
        "available_timezones": available_timezones
    }

@router.post("/config")
def update_ntp_config(req: NtpConfigRequest):
    CHRONY_CONF_DIR.mkdir(parents=True, exist_ok=True)
    CHRONY_SOURCES_DIR.mkdir(parents=True, exist_ok=True)

    conf_lines = [
        "# ZclockID Active Directory Authoritative NTP Server Configuration",
        "# Managed automatically by ZclockID Management Console"
    ]
    if req.ms_sntp_enabled:
        conf_lines.append("ntpsigndsocket /var/lib/samba/ntp_signd")

    if req.ntp_server_enabled:
        subnets = [s.strip() for s in req.allowed_subnets.replace(";", ",").split(",") if s.strip()]
        if not subnets:
            subnets = ["0.0.0.0/0", "::/0"]
        for sub in subnets:
            conf_lines.append(f"allow {sub}")
        conf_lines.append("local stratum 10 orphan")

    with open("/tmp/zclockid-ntp-server.conf.tmp", "w") as f:
        f.write("\n".join(conf_lines) + "\n")
    run_cmd(["cp", "/tmp/zclockid-ntp-server.conf.tmp", str(ZCLOCK_NTP_CONF)])

    src_lines = [
        "# ZclockID Upstream Time Sources",
        "# Managed automatically by ZclockID Management Console"
    ]
    servers = [s.strip() for s in req.upstream_servers if s.strip()]
    if not servers:
        servers = ["time.google.com", "pool.ntp.org", "time.windows.com"]
    for srv in servers:
        src_lines.append(f"pool {srv} iburst maxsources 4")

    with open("/tmp/zclockid-upstream.sources.tmp", "w") as f:
        f.write("\n".join(src_lines) + "\n")
    run_cmd(["cp", "/tmp/zclockid-upstream.sources.tmp", str(ZCLOCK_NTP_SOURCES)])

    if req.timezone and req.timezone.strip():
        run_cmd(["timedatectl", "set-timezone", req.timezone.strip()])

    code, _, err = run_cmd(["systemctl", "restart", "chrony"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to restart chrony: {err}")

    log_audit("NTP_CONFIG_UPDATED", "admin", "chrony", "SUCCESS", {
        "ntp_server_enabled": req.ntp_server_enabled,
        "ms_sntp_enabled": req.ms_sntp_enabled,
        "servers": servers,
        "timezone": req.timezone
    })
    return {"status": "success", "message": "NTP server and time synchronization settings updated successfully."}

@router.post("/sync-now")
def trigger_ntp_sync_now():
    code, out, err = run_cmd(["chronyc", "makestep"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to force clock step: {err or out}")
    log_audit("NTP_MAKESTEP_TRIGGERED", "admin", "chrony", "SUCCESS", {})
    return {"status": "success", "message": out.strip() or "Clock stepped successfully."}
