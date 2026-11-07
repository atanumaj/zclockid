#!/usr/bin/env bash
# /usr/local/bin/zclock-telemetry.sh
# Telemetry helper for SNMP and Prometheus on ZclockID Appliance

set -eo pipefail

COMMAND="${1:-status}"

case "$COMMAND" in
    ad_status)
        if systemctl is-active --quiet samba-ad-dc; then
            echo "HEALTHY"
        else
            echo "CRITICAL"
        fi
        ;;

    drs_health)
        # Check DRS replication failure counts across all partitions
        if command -v samba-tool >/dev/null 2>&1; then
            FAILURES=$(samba-tool drs showrepl 2>/dev/null | grep -i "consecutive failure" | awk '{print $1}' | awk '{s+=$1} END {print s+0}')
            echo "${FAILURES:-0}"
        else
            echo "0"
        fi
        ;;

    active_sessions)
        # Active SMB connections to this Domain Controller
        if command -v smbstatus >/dev/null 2>&1; then
            SESSIONS=$(smbstatus -b 2>/dev/null | tail -n +5 | grep -v "^$" | wc -l | tr -d ' ')
            echo "${SESSIONS:-0}"
        else
            echo "0"
        fi
        ;;

    sysvol_health)
        # Validate Windows NTACL consistency on Sysvol
        if command -v samba-tool >/dev/null 2>&1; then
            if samba-tool ntacl sysvolcheck >/dev/null 2>&1; then
                echo "HEALTHY"
            else
                echo "ACL_MISMATCH"
            fi
        else
            echo "UNKNOWN"
        fi
        ;;

    radius_auths)
        # Check FreeRADIUS status
        if systemctl is-active --quiet freeradius; then
            echo "ACTIVE"
        else
            echo "INACTIVE"
        fi
        ;;

    *)
        echo "Usage: $0 {ad_status|drs_health|active_sessions|sysvol_health|radius_auths}"
        exit 1
        ;;
esac

