"""
ZclockID Enterprise Management Appliance - Encrypted DNS (BIND9 DLZ & DoH) Router
Handles Forward/Reverse DNS lookup zones, A/CNAME/SRV records, upstream forwarders,
and RFC 8484 DNS-over-HTTPS (DoH) resolution tests.
"""

from fastapi import APIRouter, HTTPException, status, Request
import re
import os
import time
import base64
import ssl
import urllib.request
from typing import Dict, Any, List, Optional
import dns.message
import dns.rdatatype
import dns.rcode
from api.core.config import BIND_OPTIONS_FILE, SMB_CONF_FILE
from api.core.security import get_ad_creds
from api.services.system_service import run_cmd, log_audit
from api.schemas.dns_schema import (
    DnsRecordRequest,
    DnsForwardersRequest,
    DnsZoneCreateRequest,
    DohTestRequest
)

router = APIRouter(prefix="/api/v1/dns", tags=["DNS Services (BIND9 DLZ & DoH)"])

@router.get("/forwarders")
def get_dns_forwarders():
    """Reads upstream DNS forwarders from BIND9 configuration."""
    forwarders = ["1.1.1.1", "8.8.8.8"]
    policy = "first"
    if BIND_OPTIONS_FILE.exists():
        try:
            with open(BIND_OPTIONS_FILE) as f:
                content = f.read()
                m = re.search(r'forwarders\s*\{([^}]+)\};', content, re.DOTALL)
                if m:
                    raw = m.group(1)
                    parsed = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw)
                    if parsed: forwarders = parsed
                if "forward only;" in content:
                    policy = "only"
        except Exception:
            pass
    return {"forwarders": forwarders, "policy": policy}

@router.post("/forwarders")
def update_dns_forwarders(req: DnsForwardersRequest):
    """Updates upstream DNS forwarders in BIND9 configuration and reloads service."""
    if not req.forwarders:
        raise HTTPException(status_code=400, detail="At least one DNS forwarder IP is required.")
    
    ips_block = "\n".join([f"        {ip.strip()};" for ip in req.forwarders if ip.strip()])
    policy_line = "    forward only;\n" if req.policy == "only" else ""

    if BIND_OPTIONS_FILE.exists():
        try:
            with open(BIND_OPTIONS_FILE) as f:
                content = f.read()
            new_block = f"""    forwarders {{\n{ips_block}\n    }};\n{policy_line}"""
            if re.search(r'forwarders\s*\{[^}]+\};(\s*forward\s+only;)?', content):
                content = re.sub(r'forwarders\s*\{[^}]+\};(\s*forward\s+only;)?', new_block.strip(), content)
            else:
                content = content.replace("options {", f"options {{\n{new_block}")

            with open(BIND_OPTIONS_FILE, "w") as f:
                f.write(content)

            code, stdout, stderr = run_cmd(["named-checkconf", str(BIND_OPTIONS_FILE)], timeout=5)
            if code != 0:
                raise HTTPException(status_code=400, detail=f"BIND configuration syntax error: {stderr}")

            run_cmd(["systemctl", "reload", "bind9"])
            log_audit("DNS_FORWARDERS_UPDATED", "admin", "bind9", "SUCCESS", {"forwarders": req.forwarders})
            return {"status": "success", "message": "DNS forwarders updated and BIND9 reloaded.", "forwarders": req.forwarders}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to write named.conf.options: {e}")
    else:
        raise HTTPException(status_code=500, detail="named.conf.options not found.")

@router.get("/zones")
def list_dns_zones():
    """Lists all Active Directory integrated DNS zones."""
    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd(["samba-tool", "dns", "zonelist", "127.0.0.1", f"-U{admin_user}", f"--password={admin_pass}"], timeout=10)
    zones = []
    if code == 0:
        for line in stdout.splitlines():
            if "pszZoneName" in line:
                z = line.split(":")[-1].strip()
                zones.append(z)
    if not zones:
        zones = ["inet.net", "_msdcs.inet.net"]
    return {"zones": zones}

@router.post("/zones")
def create_dns_zone(req: DnsZoneCreateRequest):
    """Creates a new Active Directory integrated DNS forward or reverse lookup zone."""
    admin_user, admin_pass = get_ad_creds()
    cmd = ["samba-tool", "dns", "zonecreate", "127.0.0.1", req.zone_name.strip().lower(), f"-U{admin_user}", f"--password={admin_pass}"]
    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to create zone: {stderr or stdout}")
    log_audit("DNS_ZONE_CREATED", "admin", req.zone_name, "SUCCESS", {})
    return {"status": "success", "message": f"DNS Zone '{req.zone_name}' created successfully."}

_DNS_RECORDS_CACHE = {}

def fast_get_dns_records(zone: str):
    """High-speed in-process RPC query using Samba DnsConnWrapper (executes in ~30ms)."""
    try:
        from samba.netcmd.dns import DnsConnWrapper
        from samba.param import LoadParm
        from samba.credentials import Credentials
        from samba.dcerpc import dnsserver, dnsp

        admin_user, admin_pass = get_ad_creds()
        lp = LoadParm()
        lp.load(str(SMB_CONF_FILE))
        creds = Credentials()
        creds.guess(lp)
        creds.set_username(admin_user)
        creds.set_password(admin_pass)

        dns_conn = DnsConnWrapper("127.0.0.1", lp, creds)

        records = []
        queue = ["@"]
        visited = set()

        while queue and len(visited) < 40:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)

            try:
                buflen, res = dns_conn.DnssrvEnumRecords2(
                    dnsserver.DNS_CLIENT_VERSION_LONGHORN, 0, "127.0.0.1", zone, node,
                    None, 0xff, dnsserver.DNS_RPC_VIEW_AUTHORITY_DATA, None, None
                )
                if res and hasattr(res, "rec"):
                    for rec in res.rec:
                        node_name = rec.dnsNodeName.str if hasattr(rec.dnsNodeName, "str") else str(rec.dnsNodeName)
                        full_name = node if not node_name else (f"{node_name}.{node}" if node != "@" else node_name)

                        if hasattr(rec, "dwChildCount") and rec.dwChildCount > 0:
                            child = node_name
                            full_child = f"{child}.{node}" if node != "@" else child
                            if full_child not in visited and full_child not in queue:
                                queue.append(full_child)

                        for r in rec.records:
                            rtype = "UNKNOWN"
                            rdata = ""
                            if r.wType == dnsp.DNS_TYPE_A:
                                rtype = "A"
                                rdata = str(r.data)
                            elif r.wType == dnsp.DNS_TYPE_AAAA:
                                rtype = "AAAA"
                                rdata = str(r.data)
                            elif r.wType == dnsp.DNS_TYPE_CNAME:
                                rtype = "CNAME"
                                rdata = str(r.data.str)
                            elif r.wType == dnsp.DNS_TYPE_NS:
                                rtype = "NS"
                                rdata = str(r.data.str)
                            elif r.wType == dnsp.DNS_TYPE_SOA:
                                rtype = "SOA"
                                rdata = f"serial={r.data.dwSerialNo}, refresh={r.data.dwRefresh}, retry={r.data.dwRetry}, expire={r.data.dwExpire}, minttl={r.data.dwMinimumTtl}, ns={r.data.NamePrimaryServer.str}, email={r.data.ZoneAdministratorEmail.str}"
                            elif r.wType == dnsp.DNS_TYPE_SRV:
                                rtype = "SRV"
                                rdata = f"{r.data.nameTarget.str} ({r.data.wPort}, {r.data.wPriority}, {r.data.wWeight})"
                            elif r.wType == dnsp.DNS_TYPE_TXT:
                                rtype = "TXT"
                                rdata = ",".join([s.str for s in r.data.str])
                            elif r.wType == dnsp.DNS_TYPE_PTR:
                                rtype = "PTR"
                                rdata = str(r.data.str)
                            elif r.wType == dnsp.DNS_TYPE_MX:
                                rtype = "MX"
                                rdata = f"{r.data.nameExchange.str} ({r.data.wPreference})"

                            records.append({
                                "name": full_name,
                                "type": rtype,
                                "data": rdata,
                                "zone": zone,
                                "is_srv": (rtype == "SRV")
                            })
            except Exception:
                pass

        return records
    except Exception as e:
        logger.warning(f"Fast in-process DNS query failed ({e}), falling back to CLI")
        return None

@router.get("/records")
def get_dns_records(zone: str = "inet.net", refresh: bool = False):
    """Queries all DNS records in a zone hierarchically with high-speed in-process RPC and caching."""
    now = time.time()
    if not refresh and zone in _DNS_RECORDS_CACHE:
        cached_time, cached_records = _DNS_RECORDS_CACHE[zone]
        if now - cached_time < 10:  # 10s TTL
            return {"zone": zone, "count": len(cached_records), "records": cached_records, "cached": True}

    # 1. High-Speed In-Process RPC Query (~0.03s)
    fast_records = fast_get_dns_records(zone)
    if fast_records is not None:
        _DNS_RECORDS_CACHE[zone] = (now, fast_records)
        return {"zone": zone, "count": len(fast_records), "records": fast_records, "cached": False}

    # 2. Fallback to CLI subprocess loop
    admin_user, admin_pass = get_ad_creds()
    records = []
    visited = set()
    queue = ["@"]

    while queue and len(visited) < 40:
        node = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)

        code, stdout, _ = run_cmd([
            "samba-tool", "dns", "query", "127.0.0.1", zone, node, "ALL",
            f"-U{admin_user}", f"--password={admin_pass}"
        ], timeout=8)

        if code != 0:
            continue

        current_name = node
        for line in stdout.splitlines():
            if line.startswith("  Name="):
                m = re.search(r'Name=([^,]*), Records=(\d+), Children=(\d+)', line)
                if m:
                    sub_name = m.group(1).strip()
                    num_children = int(m.group(3))
                    full_name = f"{sub_name}.{node}" if node != "@" else sub_name if sub_name else node
                    current_name = full_name
                    if num_children > 0 and full_name not in visited and full_name not in queue:
                        queue.append(full_name)
            elif line.startswith("    "):
                parts = line.strip().split(":", 1)
                if len(parts) == 2:
                    rtype = parts[0].strip()
                    rdata = re.sub(r'\(flags=[^)]+\)', '', parts[1]).strip()
                    records.append({
                        "name": current_name,
                        "type": rtype,
                        "data": rdata,
                        "zone": zone,
                        "is_srv": (rtype == "SRV")
                    })

    _DNS_RECORDS_CACHE[zone] = (now, records)
    return {"zone": zone, "count": len(records), "records": records, "cached": False}

@router.get("/doh/status")
def get_doh_status(request: Request):
    """Returns DNS-over-HTTPS (DoH) listener status, URLs, and RFC 8484 compliance details."""
    host_hdr = request.headers.get("host", "192.168.1.41").split(":")[0]
    appliance_ip = "192.168.1.41"
    
    code_ss, out_ss, _ = run_cmd(["ss", "-tlpn"])
    is_bind_doh = (code_ss == 0 and ":8053" in out_ss and "named" in out_ss)

    realm = "inet.net"
    if SMB_CONF_FILE.exists():
        with open(SMB_CONF_FILE) as f:
            for l in f:
                if "realm =" in l:
                    realm = l.split("=")[1].strip().lower()

    code_hn, out_hn, _ = run_cmd(["hostname", "-s"])
    hostname = out_hn.strip() if code_hn == 0 and out_hn.strip() else "inet-zclockid"
    fqdn = f"{hostname}.{realm}"

    return {
        "status": "ACTIVE" if is_bind_doh else "INACTIVE",
        "service": "BIND9 (named) HTTP/2 + Nginx TLS Ingress",
        "rfc_standard": "RFC 8484 (DNS Queries over HTTPS)",
        "ingress_port": 443,
        "backend_port": 8053,
        "doh_url_ip": f"https://{appliance_ip}/dns-query",
        "doh_url_fqdn": f"https://{fqdn}/dns-query",
        "doh_url_custom": f"https://{host_hdr}/dns-query" if host_hdr != appliance_ip else f"https://{appliance_ip}/dns-query",
        "supported_methods": [
            "GET /dns-query?dns={base64url}",
            "POST /dns-query (Content-Type: application/dns-message)"
        ],
        "dnssec_validation": "Active Directory Native",
        "upstream_forwarders": ["1.1.1.1", "8.8.8.8"]
    }

@router.post("/doh/test")
def test_doh_resolution(req: DohTestRequest):
    """Executes a live DNS-over-HTTPS (DoH) query via RFC 8484 and decodes response."""
    target_qname = (req.qname or req.query_name or "inet.net").strip()
    target_rtype = (req.rtype or req.query_type or "A").strip().upper()

    try:
        q = dns.message.make_query(target_qname, target_rtype)
        wire_query = q.to_wire()
        b64_dns = base64.urlsafe_b64encode(wire_query).decode("utf-8").rstrip("=")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        start_time = time.time()
        doh_url = f"https://127.0.0.1/dns-query?dns={b64_dns}"
        req_obj = urllib.request.Request(doh_url, headers={"Accept": "application/dns-message"})

        with urllib.request.urlopen(req_obj, context=ctx, timeout=6) as resp:
            data = resp.read()
            duration_ms = round((time.time() - start_time) * 1000, 2)
            resp_msg = dns.message.from_wire(data)

            raw_answers = []
            formatted_answers = []
            for rrset in resp_msg.answer:
                for item in rrset:
                    rd_text = str(item)
                    type_str = dns.rdatatype.to_text(rrset.rdtype)
                    raw_answers.append({
                        "name": str(rrset.name),
                        "type": type_str,
                        "ttl": rrset.ttl,
                        "data": rd_text
                    })
                    formatted_answers.append(f"{str(rrset.name)} {rrset.ttl}s {type_str} {rd_text}")

            rcode_text = dns.rcode.to_text(resp_msg.rcode())
            return {
                "status": "ok",
                "success": True,
                "http_status": resp.status,
                "status_code": resp.status,
                "rcode": rcode_text,
                "latency_ms": duration_ms,
                "response_time_ms": duration_ms,
                "rtype": target_rtype,
                "answers": formatted_answers,
                "raw_answers": raw_answers,
                "answer_count": len(raw_answers),
                "query": f"{target_qname} IN {target_rtype}",
                "message": f"Successfully resolved {target_qname} via DoH in {duration_ms}ms ({len(raw_answers)} answers)."
            }
    except Exception as e:
        return {
            "status": "error",
            "success": False,
            "detail": str(e),
            "error": f"DoH query failed: {str(e)}",
            "query": f"{target_qname} IN {target_rtype}"
        }

@router.post("/records")
def add_dns_record(req: DnsRecordRequest):
    """Adds a standard (A, AAAA, CNAME, MX, TXT) or Kerberos SRV record."""
    admin_user, admin_pass = get_ad_creds()
    if req.record_type == "SRV":
        port = req.port or 88
        priority = req.priority or 0
        weight = req.weight or 100
        target = req.record_data.strip()
        srv_data = f"{target} {port} {priority} {weight}"
        cmd = ["samba-tool", "dns", "add", "127.0.0.1", req.zone, req.record_name, "SRV", srv_data, f"-U{admin_user}", f"--password={admin_pass}"]
    else:
        cmd = ["samba-tool", "dns", "add", "127.0.0.1", req.zone, req.record_name, req.record_type, req.record_data, f"-U{admin_user}", f"--password={admin_pass}"]

    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to add DNS record: {stderr or stdout}")

    _DNS_RECORDS_CACHE.pop(req.zone, None)
    log_audit("DNS_RECORD_ADDED", "admin", f"{req.record_name}.{req.zone}", "SUCCESS", {"type": req.record_type, "data": req.record_data})
    return {"status": "success", "message": f"{req.record_type} record '{req.record_name}' added to zone {req.zone}."}

@router.delete("/records")
def delete_dns_record(zone: str, record_name: str, record_type: str, record_data: str):
    """Deletes a DNS record from Active Directory DNS."""
    admin_user, admin_pass = get_ad_creds()
    cmd = ["samba-tool", "dns", "delete", "127.0.0.1", zone, record_name, record_type, record_data, f"-U{admin_user}", f"--password={admin_pass}"]
    code, stdout, stderr = run_cmd(cmd, timeout=15)
    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to delete DNS record: {stderr or stdout}")

    _DNS_RECORDS_CACHE.pop(zone, None)
    log_audit("DNS_RECORD_DELETED", "admin", f"{record_name}.{zone}", "SUCCESS", {"type": record_type})
    return {"status": "success", "message": f"Record '{record_name}' deleted from zone {zone}."}

@router.get("/diagnostics")
def get_dns_diagnostics():
    """Runs verification tests for Kerberos, LDAP, and Kpasswd service discovery records."""
    realm = "inet.net"
    if SMB_CONF_FILE.exists():
        with open(SMB_CONF_FILE) as f:
            for line in f:
                if "realm =" in line:
                    realm = line.split("=")[1].strip().lower()

    checks = []
    code_k, out_k, _ = run_cmd(["dig", "+short", f"_kerberos._tcp.{realm}", "SRV", "@127.0.0.1"], timeout=5)
    checks.append({
        "service": "Kerberos KDC (TCP Port 88)",
        "record": f"_kerberos._tcp.{realm}",
        "status": "PASS" if code_k == 0 and out_k.strip() else "FAIL",
        "result": out_k.strip() or "No SRV record returned"
    })
    code_l, out_l, _ = run_cmd(["dig", "+short", f"_ldap._tcp.{realm}", "SRV", "@127.0.0.1"], timeout=5)
    checks.append({
        "service": "LDAP Directory (TCP Port 389)",
        "record": f"_ldap._tcp.{realm}",
        "status": "PASS" if code_l == 0 and out_l.strip() else "FAIL",
        "result": out_l.strip() or "No SRV record returned"
    })
    code_p, out_p, _ = run_cmd(["dig", "+short", f"_kpasswd._tcp.{realm}", "SRV", "@127.0.0.1"], timeout=5)
    checks.append({
        "service": "Kerberos Password Change (TCP Port 464)",
        "record": f"_kpasswd._tcp.{realm}",
        "status": "PASS" if code_p == 0 and out_p.strip() else "FAIL",
        "result": out_p.strip() or "No SRV record returned"
    })
    code_f, out_f, _ = run_cmd(["dig", "+short", "cloudflare.com", "A", "@127.0.0.1"], timeout=5)
    checks.append({
        "service": "Upstream DNS Forwarding Recursion",
        "record": "cloudflare.com (A)",
        "status": "PASS" if code_f == 0 and out_f.strip() else "FAIL",
        "result": out_f.strip().splitlines()[0] if out_f.strip() else "Upstream resolution failed"
    })

    all_passed = all(c["status"] == "PASS" for c in checks)
    return {
        "status": "HEALTHY" if all_passed else "DEGRADED",
        "realm": realm,
        "diagnostics": checks
    }

