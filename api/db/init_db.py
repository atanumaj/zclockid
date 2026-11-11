"""
ZclockID Enterprise Management Appliance - SQLite Database Initialization & Schema Migrations
Manages local application policies, guest self-registrations, MAB devices, and audit logging.
Note: Active Directory accounts are stored in Samba sam.ldb, NOT in SQLite (Zero-Shadow Rule).
"""

import sqlite3
import time
from api.core.config import DB_PATH

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Admin users for Web GUI authentication
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at REAL,
            last_login REAL
        )
    """)

    # Active web sessions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT DEFAULT 'fulladmin',
            created_at REAL,
            expires_at REAL
        )
    """)
    # Migration: ensure role column exists in sessions
    cursor.execute("PRAGMA table_info(sessions)")
    sess_cols = [row[1] for row in cursor.fetchall()]
    if "role" not in sess_cols:
        cursor.execute("ALTER TABLE sessions ADD COLUMN role TEXT DEFAULT 'fulladmin'")
    if "last_active" not in sess_cols:
        cursor.execute("ALTER TABLE sessions ADD COLUMN last_active REAL")
    if "ip_address" not in sess_cols:
        cursor.execute("ALTER TABLE sessions ADD COLUMN ip_address TEXT DEFAULT ''")
    if "user_agent" not in sess_cols:
        cursor.execute("ALTER TABLE sessions ADD COLUMN user_agent TEXT DEFAULT ''")

    # Self-Registration Queue
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS self_registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            given_name TEXT,
            surname TEXT,
            department TEXT,
            mobile TEXT,
            status TEXT DEFAULT 'PENDING_OTP',
            ip_address TEXT,
            created_at REAL,
            approved_at REAL,
            approved_by TEXT,
            notes TEXT,
            otp_code TEXT,
            otp_expires_at REAL,
            otp_verified INTEGER DEFAULT 0,
            password_hash TEXT
        )
    """)

    # Column migrations for self_registrations
    cursor.execute("PRAGMA table_info(self_registrations)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    cols_to_add = {
        "mobile": "TEXT",
        "otp_code": "TEXT",
        "otp_expires_at": "REAL",
        "otp_verified": "INTEGER DEFAULT 0",
        "password_hash": "TEXT"
    }
    for col_name, col_type in cols_to_add.items():
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE self_registrations ADD COLUMN {col_name} {col_type}")

    # Self-Registration & OTP Policy Settings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS self_registration_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER DEFAULT 1,
            require_mobile_otp INTEGER DEFAULT 1,
            auto_approve_with_otp INTEGER DEFAULT 1,
            default_domain TEXT DEFAULT '',
            default_group TEXT DEFAULT 'Domain Users',
            default_bandwidth_profile_id INTEGER DEFAULT 0,
            allowed_departments TEXT DEFAULT 'Engineering,IT Operations,Finance,Human Resources,Sales & Marketing,Operations',
            sms_gateway_type TEXT DEFAULT 'simulated',
            sms_gateway_url TEXT DEFAULT '',
            sms_api_key TEXT DEFAULT '',
            sms_sender_id TEXT DEFAULT 'ZCLOCK',
            sms_template TEXT DEFAULT 'Your ZclockID verification code is {otp}. Valid for 10 minutes.',
            email_smtp_enabled INTEGER DEFAULT 0,
            smtp_host TEXT DEFAULT '',
            smtp_port INTEGER DEFAULT 587,
            smtp_user TEXT DEFAULT '',
            smtp_pass TEXT DEFAULT '',
            smtp_from TEXT DEFAULT '',
            updated_at REAL
        )
    """)

    cursor.execute("PRAGMA table_info(self_registration_settings)")
    sreg_cols = [row[1] for row in cursor.fetchall()]
    if "default_bandwidth_profile_id" not in sreg_cols:
        cursor.execute("ALTER TABLE self_registration_settings ADD COLUMN default_bandwidth_profile_id INTEGER DEFAULT 0")
    if "allowed_departments" not in sreg_cols:
        cursor.execute("ALTER TABLE self_registration_settings ADD COLUMN allowed_departments TEXT DEFAULT 'Engineering,IT Operations,Finance,Human Resources,Sales & Marketing,Operations'")
    if "use_custom_html" not in sreg_cols:
        cursor.execute("ALTER TABLE self_registration_settings ADD COLUMN use_custom_html INTEGER DEFAULT 0")
    if "custom_html_updated_at" not in sreg_cols:
        cursor.execute("ALTER TABLE self_registration_settings ADD COLUMN custom_html_updated_at REAL")

    cursor.execute("SELECT COUNT(*) FROM self_registration_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO self_registration_settings (
                id, enabled, require_mobile_otp, auto_approve_with_otp, default_domain, default_group,
                default_bandwidth_profile_id, allowed_departments, sms_gateway_type, sms_sender_id, sms_template, updated_at
            ) VALUES (
                1, 1, 1, 1, '', 'Domain Users',
                0, 'Engineering,IT Operations,Finance,Human Resources,Sales & Marketing,Operations',
                'simulated', 'ZCLOCK', 'Your ZclockID verification code is {otp}. Valid for 10 minutes.', ?
            )
        """, (time.time(),))

    # Self Service Password Settings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS self_service_password_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER DEFAULT 1,
            allow_old_password_reset INTEGER DEFAULT 1,
            allow_email_reset INTEGER DEFAULT 1,
            allow_otp_reset INTEGER DEFAULT 1,
            min_password_length INTEGER DEFAULT 8,
            require_complexity INTEGER DEFAULT 1,
            otp_expiry_minutes INTEGER DEFAULT 10,
            max_daily_attempts INTEGER DEFAULT 5,
            email_smtp_enabled INTEGER DEFAULT 0,
            smtp_host TEXT DEFAULT '',
            smtp_port INTEGER DEFAULT 587,
            smtp_user TEXT DEFAULT '',
            smtp_pass TEXT DEFAULT '',
            smtp_from TEXT DEFAULT '',
            sms_gateway_type TEXT DEFAULT 'simulated',
            sms_gateway_url TEXT DEFAULT '',
            sms_api_key TEXT DEFAULT '',
            sms_sender_id TEXT DEFAULT 'ZCLOCK',
            sms_template TEXT DEFAULT 'Your ZclockID password reset verification code is {otp}. Valid for 10 minutes.',
            use_custom_html INTEGER DEFAULT 0,
            custom_html_updated_at REAL,
            updated_at REAL
        )
    """)

    cursor.execute("PRAGMA table_info(self_service_password_settings)")
    sspr_cols = [row[1] for row in cursor.fetchall()]
    if "use_custom_html" not in sspr_cols:
        cursor.execute("ALTER TABLE self_service_password_settings ADD COLUMN use_custom_html INTEGER DEFAULT 0")
    if "custom_html_updated_at" not in sspr_cols:
        cursor.execute("ALTER TABLE self_service_password_settings ADD COLUMN custom_html_updated_at REAL")

    cursor.execute("SELECT COUNT(*) FROM self_service_password_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO self_service_password_settings (
                id, enabled, allow_old_password_reset, allow_email_reset, allow_otp_reset,
                min_password_length, require_complexity, otp_expiry_minutes, max_daily_attempts,
                sms_gateway_type, sms_sender_id, sms_template, updated_at
            ) VALUES (
                1, 1, 1, 1, 1,
                8, 1, 10, 5,
                'simulated', 'ZCLOCK', 'Your ZclockID password reset verification code is {otp}. Valid for 10 minutes.', ?
            )
        """, (time.time(),))

    # Self Service Password Reset Logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS self_service_password_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            method TEXT NOT NULL,
            recipient TEXT,
            otp_code TEXT,
            otp_expires_at REAL,
            status TEXT DEFAULT 'PENDING',
            ip_address TEXT,
            user_agent TEXT,
            created_at REAL,
            completed_at REAL,
            notes TEXT
        )
    """)

    # Index for fast month/date queries and username lookups
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sspr_logs_created ON self_service_password_logs(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sspr_logs_user ON self_service_password_logs(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_self_reg_created ON self_registrations(created_at)")

    # Audit & Reporting Events
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor TEXT,
            target TEXT,
            status TEXT,
            details TEXT,
            timestamp REAL
        )
    """)

    # RADIUS Accounting Sessions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_accounting (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            nas_ip TEXT NOT NULL,
            nas_name TEXT,
            calling_station_id TEXT,
            framed_ip TEXT,
            acct_status_type TEXT DEFAULT 'Start',
            acct_session_time INTEGER DEFAULT 0,
            input_octets INTEGER DEFAULT 0,
            output_octets INTEGER DEFAULT 0,
            terminate_cause TEXT,
            start_time REAL,
            last_update REAL
        )
    """)

    # Captive Portal Bandwidth & Rate Limiting Profiles (Pure QoS Objects)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_bandwidth_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            download_mbps REAL NOT NULL,
            upload_mbps REAL NOT NULL,
            session_timeout_mins INTEGER DEFAULT 120,
            idle_timeout_mins INTEGER DEFAULT 30,
            daily_quota_mb INTEGER DEFAULT 0,
            target_type TEXT DEFAULT 'GROUP',
            target_name TEXT DEFAULT '',
            ad_group TEXT DEFAULT '',
            is_default INTEGER DEFAULT 0,
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_at REAL
        )
    """)

    for col, ctype, cdef in [("target_type", "TEXT", "'GROUP'"), ("target_name", "TEXT", "''")]:
        try:
            cursor.execute(f"ALTER TABLE radius_bandwidth_profiles ADD COLUMN {col} {ctype} DEFAULT {cdef}")
        except Exception:
            pass

    cursor.execute("SELECT COUNT(*) FROM radius_bandwidth_profiles")
    if cursor.fetchone()[0] == 0:
        now_ts = time.time()
        cursor.execute("""
            INSERT INTO radius_bandwidth_profiles (name, download_mbps, upload_mbps, session_timeout_mins, idle_timeout_mins, daily_quota_mb, target_type, target_name, ad_group, is_default, description, is_active, created_at)
            VALUES 
            ('VIP-Executive', 50.0, 25.0, 1440, 60, 0, 'GROUP', 'Domain Admins', 'Domain Admins', 0, 'Unrestricted high-speed priority tier for leadership & admins', 1, ?),
            ('Staff-Standard', 20.0, 10.0, 720, 30, 0, 'GROUP', 'Corporate-Users', 'Corporate-Users', 0, 'Standard enterprise employee work profile', 1, ?),
            ('Guest-Captive-Portal', 5.0, 2.0, 120, 15, 2048, 'DEFAULT', 'ALL', '', 0, 'Captive portal profile for visitor Wi-Fi & OTP self-registrations', 1, ?),
            ('Limited-Public', 2.0, 0.5, 30, 10, 500, 'GROUP', '', '', 0, 'Throttled public access tier with 500 MB data cap', 1, ?)
        """, (now_ts, now_ts, now_ts, now_ts))

    # User to Bandwidth Profile Mapping
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_user_bandwidth (
            username TEXT PRIMARY KEY,
            profile_id INTEGER NOT NULL,
            updated_at REAL
        )
    """)

    # MAC Authentication Bypass (MAB) for Headless Devices
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_mab_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT NOT NULL UNIQUE,
            device_name TEXT NOT NULL,
            vlan_id INTEGER NOT NULL,
            static_ip TEXT DEFAULT '',
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_at REAL
        )
    """)

    # Custom RADIUS Vendor Attributes & Policies
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_custom_attributes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,
            target_name TEXT DEFAULT '',
            attribute_name TEXT NOT NULL,
            operator TEXT DEFAULT '=',
            attribute_value TEXT NOT NULL,
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_at REAL
        )
    """)

    # RADIUS General Configuration
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS radius_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            auth_port INTEGER DEFAULT 1812,
            acct_port INTEGER DEFAULT 1813,
            acct_enabled INTEGER DEFAULT 1,
            interim_interval INTEGER DEFAULT 300,
            listen_ip TEXT DEFAULT '0.0.0.0',
            log_auth INTEGER DEFAULT 1,
            log_badpass INTEGER DEFAULT 1,
            log_stripped_names INTEGER DEFAULT 0,
            eap_peap_enabled INTEGER DEFAULT 1,
            eap_tls_enabled INTEGER DEFAULT 1,
            eap_default_type TEXT DEFAULT 'peap',
            max_requests INTEGER DEFAULT 1024,
            max_servers INTEGER DEFAULT 32,
            updated_at REAL
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO radius_settings (id, auth_port, acct_port, acct_enabled, interim_interval, updated_at) VALUES (1, 1812, 1813, 1, 300, ?)", (time.time(),))

    # System Update & Release Management
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS update_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            github_repo TEXT DEFAULT 'atanumaj/zclockid',
            custom_manifest_url TEXT DEFAULT '',
            auto_check INTEGER DEFAULT 1,
            last_checked REAL DEFAULT 0,
            latest_version TEXT DEFAULT '',
            latest_release_name TEXT DEFAULT '',
            latest_release_notes TEXT DEFAULT '',
            latest_download_url TEXT DEFAULT '',
            last_check_status TEXT DEFAULT 'NOT_CHECKED',
            updated_at REAL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM update_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO update_settings (
                id, github_repo, custom_manifest_url, auto_check, last_checked,
                latest_version, latest_release_name, latest_release_notes,
                latest_download_url, last_check_status, updated_at
            ) VALUES (
                1, 'atanumaj/zclockid', '', 1, 0, '', '', '', '', 'NOT_CHECKED', ?
            )
        """, (time.time(),))

    # RBAC Role Mappings (Active Directory Users / Groups -> Appliance Roles)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rbac_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            principal_type TEXT NOT NULL,
            principal_name TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            description TEXT,
            created_at REAL,
            updated_at REAL
        )
    """)
    # Seed default RBAC mappings
    cursor.execute("""
        INSERT OR IGNORE INTO rbac_mappings (principal_type, principal_name, role, description, created_at, updated_at)
        VALUES 
            ('group', 'Domain Admins', 'fulladmin', 'Active Directory Domain Administrators', ?, ?),
            ('group', 'Enterprise Admins', 'fulladmin', 'Active Directory Enterprise Administrators', ?, ?)
    """, (time.time(), time.time(), time.time(), time.time()))

    # API Keys Management
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            scopes TEXT NOT NULL,
            cidr_whitelist TEXT DEFAULT '0.0.0.0/0',
            expires_at REAL,
            last_used_at REAL,
            is_active INTEGER DEFAULT 1,
            created_at REAL
        )
    """)

    # Syslog Remote Forwarding & Settings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS syslog_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER DEFAULT 0,
            remote_host TEXT DEFAULT '',
            remote_port INTEGER DEFAULT 514,
            protocol TEXT DEFAULT 'UDP',
            facility TEXT DEFAULT 'local0',
            log_format TEXT DEFAULT 'RFC5424',
            send_samba_logs INTEGER DEFAULT 1,
            send_radius_logs INTEGER DEFAULT 1,
            send_auth_logs INTEGER DEFAULT 1,
            send_system_logs INTEGER DEFAULT 1,
            updated_at REAL
        )
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO syslog_settings (id, enabled, remote_host, remote_port, protocol, facility, log_format, updated_at)
        VALUES (1, 0, '', 514, 'UDP', 'local0', 'RFC5424', ?)
    """, (time.time(),))

    # System-Wide Security Controls & Baseline Settings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            session_idle_timeout_min INTEGER DEFAULT 15,
            session_max_lifetime_hours INTEGER DEFAULT 8,
            allowed_subnets_gui TEXT DEFAULT '0.0.0.0/0, ::/0',
            allowed_subnets_ssh TEXT DEFAULT '0.0.0.0/0, ::/0',
            allowed_subnets_snmp TEXT DEFAULT '192.168.1.0/24, 10.10.0.0/24, 127.0.0.1/32',
            snmp_community TEXT DEFAULT 'zclock_public',
            max_failed_logins INTEGER DEFAULT 5,
            lockout_duration_min INTEGER DEFAULT 15,
            ssh_permit_root INTEGER DEFAULT 0,
            ssh_password_auth INTEGER DEFAULT 1,
            updated_at REAL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM security_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO security_settings (
                id, session_idle_timeout_min, session_max_lifetime_hours,
                allowed_subnets_gui, allowed_subnets_ssh, allowed_subnets_snmp,
                snmp_community, max_failed_logins, lockout_duration_min,
                ssh_permit_root, ssh_password_auth, updated_at
            ) VALUES (1, 15, 8, '0.0.0.0/0, ::/0', '0.0.0.0/0, ::/0', '192.168.1.0/24, 10.10.0.0/24, 127.0.0.1/32', 'zclock_public', 5, 15, 0, 1, ?)
        """, (time.time(),))

    # Failed login attempts for brute-force rate-limiting and lockout
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS failed_login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username TEXT NOT NULL,
            timestamp REAL NOT NULL
        )
    """)

    # Appliance Host Firewall Configuration & Rules
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS firewall_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            is_enabled INTEGER DEFAULT 0,
            default_incoming TEXT DEFAULT 'DENY',
            default_outgoing TEXT DEFAULT 'ALLOW',
            updated_at REAL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM firewall_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO firewall_settings (id, is_enabled, default_incoming, default_outgoing, updated_at)
            VALUES (1, 0, 'DENY', 'ALLOW', ?)
        """, (time.time(),))

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type TEXT DEFAULT 'custom',
            action TEXT DEFAULT 'ALLOW',
            protocol TEXT DEFAULT 'TCP',
            port TEXT NOT NULL,
            source TEXT DEFAULT 'Any',
            comment TEXT,
            is_enabled INTEGER DEFAULT 1,
            created_at REAL,
            updated_at REAL
        )
    """)

    # Seed required Active Directory, DNS, Kerberos, RADIUS, and Management ports
    cursor.execute("SELECT COUNT(*) FROM firewall_rules WHERE rule_type = 'system'")
    if cursor.fetchone()[0] == 0:
        now = time.time()
        system_rules = [
            ("system", "ALLOW", "TCP", "22", "Any", "Administrative SSH Access", 1, now, now),
            ("system", "ALLOW", "TCP", "443", "Any", "Web Console HTTPS Access", 1, now, now),
            ("system", "ALLOW", "TCP", "80", "Any", "Web Console HTTP Redirect", 1, now, now),
            ("system", "ALLOW", "BOTH", "53", "Any", "DNS Server (BIND9 DLZ / DoH)", 1, now, now),
            ("system", "ALLOW", "BOTH", "88", "Any", "Active Directory Kerberos KDC", 1, now, now),
            ("system", "ALLOW", "BOTH", "464", "Any", "Kerberos Password Change (kpasswd)", 1, now, now),
            ("system", "ALLOW", "BOTH", "389", "Any", "Active Directory LDAP Directory Service", 1, now, now),
            ("system", "ALLOW", "TCP", "636", "Any", "Active Directory Secure LDAP (LDAPS)", 1, now, now),
            ("system", "ALLOW", "TCP", "3268", "Any", "Active Directory Global Catalog (GC)", 1, now, now),
            ("system", "ALLOW", "TCP", "3269", "Any", "Active Directory Secure Global Catalog", 1, now, now),
            ("system", "ALLOW", "TCP", "445", "Any", "Active Directory SMB & Sysvol Replication", 1, now, now),
            ("system", "ALLOW", "TCP", "139", "Any", "NetBIOS Session Service", 1, now, now),
            ("system", "ALLOW", "UDP", "137", "Any", "NetBIOS Name Service (NBNS)", 1, now, now),
            ("system", "ALLOW", "UDP", "138", "Any", "NetBIOS Datagram Service", 1, now, now),
            ("system", "ALLOW", "TCP", "135", "Any", "MS-RPC Endpoint Mapper", 1, now, now),
            ("system", "ALLOW", "TCP", "49152:65535", "Any", "Active Directory RPC Dynamic Ports", 1, now, now),
            ("system", "ALLOW", "UDP", "1812", "Any", "FreeRADIUS 802.1X Authentication", 1, now, now),
            ("system", "ALLOW", "UDP", "1813", "Any", "FreeRADIUS Session Accounting", 1, now, now),
            ("system", "ALLOW", "UDP", "123", "Any", "Chrony Enterprise NTP Server", 1, now, now),
            ("system", "ALLOW", "UDP", "161", "Any", "Net-SNMP Appliance Telemetry", 1, now, now)
        ]
        cursor.executemany("""
            INSERT INTO firewall_rules (rule_type, action, protocol, port, source, comment, is_enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, system_rules)

    conn.commit()
    conn.close()

