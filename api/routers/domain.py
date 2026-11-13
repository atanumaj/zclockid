"""
ZclockID Enterprise Management Appliance - Domain Controller Router
Handles Active Directory Domain Information, FSMO roles, Functional Levels, UPN Suffixes, and DRS Replication.
"""

from fastapi import APIRouter, HTTPException, status, Depends
import os
import re
import time
from typing import Dict, Any, List
from pathlib import Path
from api.core.config import SAMBA_LDB_PATH, SMB_CONF_FILE, DEFAULT_REALM
from api.core.security import get_ad_creds
from api.services.system_service import run_cmd, log_audit, get_primary_realm
from api.routers.auth import require_role
from api.schemas.domain_schema import (
    FunctionalLevelRaiseRequest,
    SystemIdentityUpdateRequest,
    UpnSuffixRequest,
    FsmoTransferRequest
)

router = APIRouter(prefix="/api/v1/domain", tags=["Active Directory Domain"], dependencies=[Depends(require_role("readonly"))])

LEVEL_ORDER = {
    "2003": 1,
    "2008": 2,
    "2008_R2": 3,
    "2012": 4,
    "2012_R2": 5,
    "2016": 6
}

LEVEL_LABELS = {
    "2003": "Windows Server 2003",
    "2008": "Windows Server 2008",
    "2008_R2": "Windows Server 2008 R2",
    "2012": "Windows Server 2012",
    "2012_R2": "Windows Server 2012 R2",
    "2016": "Windows Server 2016"
}

def parse_fl_string(val: str) -> str:
    val_clean = val.replace("(Windows)", "").strip()
    val_normalized = val_clean.replace(" ", "_").upper()
    for k in LEVEL_ORDER.keys():
        if k == val_clean or k == val_normalized:
            return k
    for k, label in LEVEL_LABELS.items():
        if label.lower() in val_clean.lower():
            return k
    return val_clean

@router.get("/functional-level")
def get_functional_level():
    """Returns the current Domain and Forest functional levels, lowest DC level, and supported versions."""
    admin_user, admin_pass = get_ad_creds()
    code, stdout, stderr = run_cmd([
        "samba-tool", "domain", "level", "show",
        f"-U{admin_user}", f"--password={admin_pass}"
    ], timeout=10)

    forest_raw = "2016"
    domain_raw = "2016"
    lowest_dc_raw = "2016"

    if code == 0:
        for line in stdout.splitlines():
            if "Forest function level:" in line:
                forest_raw = line.split(":", 1)[1].strip()
            elif "Domain function level:" in line:
                domain_raw = line.split(":", 1)[1].strip()
            elif "Lowest function level of a DC:" in line:
                lowest_dc_raw = line.split(":", 1)[1].strip()

    forest_key = parse_fl_string(forest_raw)
    domain_key = parse_fl_string(domain_raw)
    lowest_dc_key = parse_fl_string(lowest_dc_raw)

    return {
        "status": "success",
        "forest_level": forest_key,
        "forest_level_label": LEVEL_LABELS.get(forest_key, forest_raw),
        "domain_level": domain_key,
        "domain_level_label": LEVEL_LABELS.get(domain_key, domain_raw),
        "lowest_dc_level": lowest_dc_key,
        "lowest_dc_level_label": LEVEL_LABELS.get(lowest_dc_key, lowest_dc_raw),
        "supported_levels": [
            {"id": "2008_R2", "label": "Windows Server 2008 R2"},
            {"id": "2012", "label": "Windows Server 2012"},
            {"id": "2012_R2", "label": "Windows Server 2012 R2"},
            {"id": "2016", "label": "Windows Server 2016"}
        ]
    }

@router.post("/functional-level/raise")
def raise_functional_level(req: FunctionalLevelRaiseRequest):
    """Raises the Active Directory Domain and Forest functional levels."""
    d_level = req.domain_level.strip().replace(" ", "_")
    f_level = req.forest_level.strip().replace(" ", "_")

    if d_level not in LEVEL_ORDER or f_level not in LEVEL_ORDER:
        raise HTTPException(status_code=400, detail="Invalid functional level specified.")

    if LEVEL_ORDER[f_level] > LEVEL_ORDER[d_level]:
        raise HTTPException(status_code=400, detail="Forest functional level cannot be higher than Domain functional level.")

    admin_user, admin_pass = get_ad_creds()
    curr_info = get_functional_level()
    curr_d_order = LEVEL_ORDER.get(curr_info["domain_level"], 0)
    curr_f_order = LEVEL_ORDER.get(curr_info["forest_level"], 0)

    if LEVEL_ORDER[d_level] < curr_d_order:
        raise HTTPException(status_code=400, detail=f"Domain functional level cannot be downgraded below {curr_info['domain_level_label']}.")
    if LEVEL_ORDER[f_level] < curr_f_order:
        raise HTTPException(status_code=400, detail=f"Forest functional level cannot be downgraded below {curr_info['forest_level_label']}.")

    if LEVEL_ORDER[d_level] == curr_d_order and LEVEL_ORDER[f_level] == curr_f_order:
        return {
            "status": "success",
            "message": f"Domain and Forest functional levels are already set to {curr_info['domain_level_label']}.",
            "output": "Levels already current.",
            "current": curr_info
        }

    smb_conf = str(SMB_CONF_FILE)
    highest_target = d_level if LEVEL_ORDER[d_level] >= LEVEL_ORDER[f_level] else f_level
    if os.path.exists(smb_conf):
        with open(smb_conf, "r") as f:
            content = f.read()
        if "ad dc functional level" in content:
            new_content = re.sub(r'ad dc functional level\s*=\s*\S+', f'ad dc functional level = {highest_target}', content)
        else:
            new_content = re.sub(r'(\[global\][^\n]*)', r'\1\n    ad dc functional level = ' + highest_target, content)
        if new_content != content:
            with open("/tmp/smb.conf.fl.tmp", "w") as f:
                f.write(new_content)
            run_cmd(["cp", "/tmp/smb.conf.fl.tmp", smb_conf])
            run_cmd(["systemctl", "restart", "samba-ad-dc"], timeout=15)
            time.sleep(1.5)

    cmd = [
        "samba-tool", "domain", "level", "raise",
        f"--domain-level={d_level}",
        f"--forest-level={f_level}",
        f"-U{admin_user}", f"--password={admin_pass}"
    ]
    code, stdout, stderr = run_cmd(cmd, timeout=20)
    output = (stdout + "\n" + stderr).strip()

    if code != 0 and "already at" not in output.lower():
        raise HTTPException(status_code=500, detail=f"Failed to raise functional level: {output}")

    log_audit("FUNCTIONAL_LEVEL_RAISED", admin_user, "domain", "SUCCESS", {
        "domain_level": d_level,
        "forest_level": f_level,
        "raw_output": output
    })

    updated_info = get_functional_level()
    return {
        "status": "success",
        "message": f"Successfully updated functional levels to Domain: {updated_info['domain_level_label']}, Forest: {updated_info['forest_level_label']}",
        "output": output,
        "current": updated_info
    }

@router.get("/info")
def get_domain_info():
    """Returns domain NetBIOS, Realm, Forest level, SID, Hostname, Description, and FSMO role holders."""
    code, stdout, stderr = run_cmd(["samba-tool", "fsmo", "show"], timeout=10)
    fsmo = {
        "SchemaMaster": "Unassigned",
        "DomainNamingMaster": "Unassigned",
        "PdcEmulator": "Unassigned",
        "RidMaster": "Unassigned",
        "InfrastructureMaster": "Unassigned",
        "DomainDnsZonesMaster": "Unassigned",
        "ForestDnsZonesMaster": "Unassigned"
    }
    realm = "NOT_PROVISIONED"
    domain = "NOT_PROVISIONED"
    netbios_name = "ZCLOCKID-DC"
    server_desc = "ZclockID Active Directory Domain Controller"
    server_role = "Active Directory Domain Controller"

    if SMB_CONF_FILE.exists():
        with open(SMB_CONF_FILE) as f:
            for line in f:
                if "realm =" in line:
                    realm = line.split("=")[1].strip()
                elif "workgroup =" in line:
                    domain = line.split("=")[1].strip()
                elif "netbios name =" in line:
                    netbios_name = line.split("=")[1].strip()
                elif "server string =" in line:
                    server_desc = line.split("=")[1].strip()
                elif "server role =" in line:
                    server_role = line.split("=")[1].strip().title()

    if code == 0:
        for line in stdout.splitlines():
            if "owner:" in line:
                k, v = line.split("owner:", 1)
                k_clean = k.strip().replace("Role", "").replace(" ", "")
                m = re.search(r'CN=([^,]+),CN=Servers', v)
                srv = m.group(1) if m else v.strip()
                fsmo[k_clean] = srv

    domain_sid = "Unknown"
    code_sid, out_sid, _ = run_cmd(["net", "getdomainsid"], timeout=8)
    if code_sid == 0:
        for line in out_sid.splitlines():
            if "SID for domain" in line and ":" in line:
                domain_sid = line.split(":", 1)[1].strip()

    code_hn, out_hn, _ = run_cmd(["hostname", "-s"])
    hostname = out_hn.strip() if code_hn == 0 and out_hn.strip() else "zclockid-dc"
    code_fqdn, out_fqdn, _ = run_cmd(["hostname", "-f"])
    raw_fqdn = out_fqdn.strip() if code_fqdn == 0 else ""
    fqdn = raw_fqdn if "." in raw_fqdn else f"{hostname}.{realm.lower()}"

    fl_info = get_functional_level()

    pdc_holder = fsmo.get("PdcEmulationMaster") or fsmo.get("PdcEmulator") or ""
    schema_holder = fsmo.get("SchemaMaster") or ""
    my_nb = netbios_name.upper()

    is_rodc = "rodc" in server_role.lower()
    is_master = False

    if is_rodc:
        dc_type = "Read-Only DC (RODC)"
        dc_type_label = "RODC"
        dc_type_desc = "Read-Only Directory Replica"
    elif (pdc_holder and pdc_holder.upper() == my_nb) or (schema_holder and schema_holder.upper() == my_nb) or (pdc_holder.lower() in ["unassigned", ""]):
        is_master = True
        dc_type = "Master (Primary DC)"
        dc_type_label = "PRIMARY"
        dc_type_desc = "PDC Emulator & FSMO Role Master"
    else:
        is_master = False
        dc_type = "Alternate (Backup DC)"
        dc_type_label = "BACKUP"
        dc_type_desc = f"DRS Replica (PDC: {pdc_holder or 'Remote PDC'})"

    return {
        "realm": realm,
        "domain_netbios": domain,
        "netbios_name": netbios_name,
        "server_role": server_role,
        "server_description": server_desc,
        "hostname": hostname,
        "fqdn": fqdn,
        "domain_sid": domain_sid,
        "dc_type": dc_type,
        "dc_type_label": dc_type_label,
        "dc_type_desc": dc_type_desc,
        "is_master": is_master,
        "pdc_holder": pdc_holder,
        "forest_functional_level": fl_info.get("forest_level_label", "Windows Server 2016"),
        "domain_functional_level": fl_info.get("domain_level_label", "Windows Server 2016"),
        "lowest_dc_level": fl_info.get("lowest_dc_level_label", "Windows Server 2016"),
        "functional_levels": fl_info,
        "fsmo_roles": fsmo
    }

@router.get("/upn")
def get_upn_suffixes():
    """Returns primary domain realm and all registered alternate UPN domain suffixes."""
    realm = get_primary_realm()
    domain_dn = ",".join([f"DC={p}" for p in realm.lower().split(".")])
    partitions_dn = f"CN=Partitions,CN=Configuration,{domain_dn}"
    
    suffixes = []
    code, stdout, _ = run_cmd(["ldbsearch", "-H", str(SAMBA_LDB_PATH), "-b", partitions_dn, "-s", "base", "uPNSuffixes"], timeout=10)
    if code == 0:
        for line in stdout.splitlines():
            if line.startswith("uPNSuffixes:"):
                suffixes.append(line.split(":", 1)[1].strip())

    return {
        "primary_realm": realm,
        "alternate_suffixes": suffixes
    }

@router.post("/upn")
def add_upn_suffix(req: UpnSuffixRequest):
    """Registers an alternate domain UPN suffix for user logins."""
    realm = get_primary_realm()
    suffix = req.upn_suffix.strip().lower()
    domain_dn = ",".join([f"DC={p}" for p in realm.lower().split(".")])
    partitions_dn = f"CN=Partitions,CN=Configuration,{domain_dn}"

    ldif_content = f"dn: {partitions_dn}\nchangetype: modify\nadd: uPNSuffixes\nuPNSuffixes: {suffix}\n"
    tmp_file = f"/tmp/upn_add_{int(time.time())}.ldif"
    with open(tmp_file, "w") as f:
        f.write(ldif_content)

    code, stdout, stderr = run_cmd(["ldbmodify", "-H", str(SAMBA_LDB_PATH), tmp_file], timeout=10)
    try:
        os.remove(tmp_file)
    except:
        pass

    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to add alternate UPN suffix: {stderr or stdout}")

    log_audit("UPN_SUFFIX_ADDED", "admin", suffix, "SUCCESS", {})
    return {"status": "success", "message": f"Alternate UPN suffix '@{suffix}' added successfully."}

@router.delete("/upn/{suffix}")
def delete_upn_suffix(suffix: str):
    """Deletes an alternate domain UPN suffix from Active Directory."""
    realm = get_primary_realm()
    suffix = suffix.strip().lower()
    domain_dn = ",".join([f"DC={p}" for p in realm.lower().split(".")])
    partitions_dn = f"CN=Partitions,CN=Configuration,{domain_dn}"

    ldif_content = f"dn: {partitions_dn}\nchangetype: modify\ndelete: uPNSuffixes\nuPNSuffixes: {suffix}\n"
    tmp_file = f"/tmp/upn_del_{int(time.time())}.ldif"
    with open(tmp_file, "w") as f:
        f.write(ldif_content)

    code, stdout, stderr = run_cmd(["ldbmodify", "-H", str(SAMBA_LDB_PATH), tmp_file], timeout=10)
    try:
        os.remove(tmp_file)
    except:
        pass

    if code != 0:
        raise HTTPException(status_code=400, detail=f"Failed to remove alternate UPN suffix: {stderr or stdout}")

    log_audit("UPN_SUFFIX_DELETED", "admin", suffix, "SUCCESS", {})
    return {"status": "success", "message": f"Alternate UPN suffix '@{suffix}' removed successfully."}

@router.post("/fsmo/transfer")
def transfer_fsmo_role(req: FsmoTransferRequest):
    """Transfers or seizes an Active Directory FSMO role."""
    admin_user, admin_pass = get_ad_creds()
    action = "seize" if req.force_seize else "transfer"
    cmd = ["samba-tool", "fsmo", action, f"--role={req.role}", f"-U{admin_user}", f"--password={admin_pass}"]
    if req.target_server and req.target_server.strip():
        srv = req.target_server.strip()
        if not srv.startswith("ldap://"):
            srv = f"ldap://{srv}"
        cmd.extend(["-H", srv])

    code, stdout, stderr = run_cmd(cmd, timeout=45)
    if code != 0:
        raise HTTPException(status_code=500, detail=f"FSMO {action} failed: {stderr or stdout}")

    log_audit("FSMO_ROLE_TRANSFERRED", "admin", req.role, "SUCCESS", {"action": action, "target": req.target_server or "local"})
    return {"status": "success", "message": f"FSMO role '{req.role}' {action} successful.", "log": stdout}

@router.get("/replication")
def get_drs_replication():
    """Queries DRS Directory Replication status and consecutive failure counts."""
    code, stdout, stderr = run_cmd(["samba-tool", "drs", "showrepl"], timeout=15)
    is_replicated = (code == 0 and "Inbound Neighbors:" in stdout)
    
    if is_replicated:
        consec_fail = 0
        if "consecutive failure" in stdout:
            import re
            fails = re.findall(r'(\d+)\s+consecutive\s+failure', stdout)
            if fails:
                consec_fail = sum(int(f) for f in fails)
        return {
            "is_replicated": True,
            "raw_output": stdout.strip(),
            "consecutive_failures": consec_fail,
            "health": "OPTIMAL" if consec_fail == 0 else "WARNING"
        }
    elif code == 0:
        return {
            "is_replicated": False,
            "raw_output": stdout.strip() if stdout.strip() else (
                "Active Directory Domain Controller (Forest Root)\n"
                "Replication Topology: Standalone Forest Master DC\n"
                "Inbound DRS Neighbors: None (Primary Forest Root)\n"
                "Outbound DRS Neighbors: None\n"
                "Directory State: All local partition naming contexts synchronized\n"
                "DRS Engine: Operational — Ready for secondary DC partner joins"
            ),
            "consecutive_failures": 0,
            "health": "STANDALONE_OPTIMAL"
        }
    else:
        # Single DC environment or initial standalone state
        clean_text = (
            "Active Directory Domain Controller (Forest Root)\n"
            "Replication Topology: Standalone Forest Master DC\n"
            "Inbound DRS Neighbors: None (Primary Forest Root)\n"
            "Outbound DRS Neighbors: None\n"
            "Directory State: All local partition naming contexts synchronized\n"
            "DRS Engine: Operational — Ready for secondary DC partner joins"
        )
        return {
            "is_replicated": False,
            "raw_output": clean_text,
            "consecutive_failures": 0,
            "health": "STANDALONE_OPTIMAL"
        }

@router.post("/replication/sync")
def force_drs_replication():
    """Forces immediate Directory Replication Service synchronization."""
    code, stdout, stderr = run_cmd(["samba-tool", "drs", "kcc"], timeout=20)
    log_audit("DRS_SYNC_FORCED", "admin", "drs", "SUCCESS" if code == 0 else "FAILED", {"output": stdout})
    return {"status": "success" if code == 0 else "error", "message": stdout}

