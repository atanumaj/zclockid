"""
api/services/samdb_service.py: In-process Samba Active Directory operations using SamDB.
Eliminates passing passwords and secrets on command line arguments.
Enforces fail-closed database connections, LDAP filter escaping, and root-only credential files.
"""
import os
import subprocess
import tempfile
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
from fastapi import HTTPException, status

from api.core.config import SAMBA_LDB_PATH, SMB_CONF_FILE
from api.core.security import get_ad_creds
from api.services.system_service import run_cmd

logger = logging.getLogger("zclockid.samdb")

try:
    import samba
    from samba.samdb import SamDB
    from samba.auth import system_session
    from samba.param import LoadParm
    HAS_SAMBA_BINDINGS = True
except ImportError:
    HAS_SAMBA_BINDINGS = False

try:
    import ldb
    HAS_LDB = True
except ImportError:
    HAS_LDB = False


class SamDBUnavailableError(HTTPException):
    """Raised when Active Directory database cannot be reached or opened."""
    def __init__(self, detail: str = "Active Directory database unavailable"):
        super().__init__(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)


def escape_ldap_filter_value(val: Optional[str]) -> str:
    """
    Escapes LDAP filter values using ldb.binary_encode() according to RFC 4515.
    Prevents LDAP filter injection and wildcard wildcard attacks (e.g. 'Administrato*').
    """
    if val is None:
        return ""
    s = str(val)
    if HAS_LDB:
        try:
            return ldb.binary_encode(s)
        except Exception:
            pass
    # Fallback RFC 4515 encoder for environments without native ldb bindings
    out = []
    for c in s:
        if c == '\\':
            out.append('\\5c')
        elif c == '*':
            out.append('\\2a')
        elif c == '(':
            out.append('\\28')
        elif c == ')':
            out.append('\\29')
        elif c == '\0':
            out.append('\\00')
        else:
            out.append(c)
    return "".join(out)


class MockSamDB:
    """Mock SamDB for testing only when explicitly enabled by ZCLOCKID_SAMDB_MOCK=1."""
    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.calls: List[Tuple[Any, ...]] = []

    def newuser(self, username, password, force_password_change_at_next_login_req=False,
                useusernameascn=False, userou=None, surname=None, givenname=None,
                department=None, mailaddress=None, telephonenumber=None, description=None, **kwargs):
        self.calls.append(("newuser", username, password, kwargs))
        self.users[username] = {
            "password": password,
            "surname": surname,
            "givenname": givenname,
            "department": department,
            "mailaddress": mailaddress,
            "telephonenumber": telephonenumber,
            "description": description,
            "enabled": True,
            "never_expires": False
        }

    def setpassword(self, search_filter, password, force_change_at_next_login=False, username=None):
        self.calls.append(("setpassword", search_filter, password, force_change_at_next_login))
        u = username
        if not u and "sAMAccountName=" in search_filter:
            u = search_filter.split("sAMAccountName=", 1)[1].rstrip(")")
        # If wildcard escaped like Administrato\2A, it does not match Administrator
        if u and u in self.users:
            self.users[u]["password"] = password
        else:
            raise KeyError(f"User not found for filter: {search_filter}")

    def setexpiry(self, search_filter, expiry_seconds, no_expiry_req=False):
        self.calls.append(("setexpiry", search_filter, expiry_seconds, no_expiry_req))
        if "sAMAccountName=" in search_filter:
            u = search_filter.split("sAMAccountName=", 1)[1].rstrip(")")
            if u in self.users:
                self.users[u]["never_expires"] = no_expiry_req

    def enable_account(self, search_filter):
        self.calls.append(("enable_account", search_filter))
        if "sAMAccountName=" in search_filter:
            u = search_filter.split("sAMAccountName=", 1)[1].rstrip(")")
            if u in self.users:
                self.users[u]["enabled"] = True

    def disable_account(self, search_filter):
        self.calls.append(("disable_account", search_filter))
        if "sAMAccountName=" in search_filter:
            u = search_filter.split("sAMAccountName=", 1)[1].rstrip(")")
            if u in self.users:
                self.users[u]["enabled"] = False

    def deleteuser(self, username):
        self.calls.append(("deleteuser", username))
        self.users.pop(username, None)

    def newgroup(self, groupname, groupou=None, grouptype=None, description=None, **kwargs):
        self.calls.append(("newgroup", groupname, description))
        self.groups[groupname] = {"description": description, "members": set()}

    def deletegroup(self, groupname):
        self.calls.append(("deletegroup", groupname))
        self.groups.pop(groupname, None)

    def add_remove_group_members(self, group, members, add_members_operation=True, **kwargs):
        self.calls.append(("add_remove_group_members", group, members, add_members_operation))
        if group not in self.groups:
            self.groups[group] = {"description": "", "members": set()}
        for m in members:
            if add_members_operation:
                self.groups[group]["members"].add(m)
            else:
                self.groups[group]["members"].discard(m)


_global_mock_samdb = MockSamDB()


def is_samba_ad_active() -> bool:
    """Checks if samba-ad-dc service is actively running on systemd hosts."""
    if os.environ.get("ZCLOCKID_SAMDB_MOCK") == "1":
        return True
    if os.path.exists("/run/systemd/system"):
        try:
            res = subprocess.run(
                ["systemctl", "is-active", "--quiet", "samba-ad-dc"],
                capture_output=True,
                timeout=3
            )
            return res.returncode == 0
        except Exception as e:
            logger.warning("Failed to check samba-ad-dc systemd status: %s", e)
            return False
    return True


def get_samdb():
    """
    Returns an initialized SamDB instance.
    Never returns MockSamDB in production. Uses MockSamDB only when explicitly enabled
    for tests (ZCLOCKID_SAMDB_MOCK=1).
    Raises SamDBUnavailableError (HTTP 503) if bindings are missing, service is stopped,
    or SamDB fails to open.
    """
    is_mock_enabled = os.environ.get("ZCLOCKID_SAMDB_MOCK") == "1"

    if not HAS_SAMBA_BINDINGS:
        if is_mock_enabled:
            return _global_mock_samdb
        logger.error("Native samba Python bindings not available and ZCLOCKID_SAMDB_MOCK!=1")
        raise SamDBUnavailableError("Active Directory database unavailable")

    if not is_samba_ad_active():
        if is_mock_enabled:
            return _global_mock_samdb
        logger.error("samba-ad-dc service is not active")
        raise SamDBUnavailableError("Active Directory database unavailable")

    try:
        lp = LoadParm()
        if os.path.exists(str(SMB_CONF_FILE)):
            lp.load(str(SMB_CONF_FILE))
        return SamDB(url=str(SAMBA_LDB_PATH), session_info=system_session(), lp=lp)
    except Exception as e:
        logger.warning("Failed to open SamDB at %s: %s", SAMBA_LDB_PATH, e)
        if is_mock_enabled:
            return _global_mock_samdb
        raise SamDBUnavailableError("Active Directory database unavailable") from e


AUTH_RUNTIME_DIR = Path(os.environ.get("ZCLOCKID_AUTH_DIR", "/run/zclockid"))


def get_auth_runtime_dir() -> Path:
    """Ensures AUTH_RUNTIME_DIR exists with mode 0700 (root-only)."""
    p = Path(os.environ.get("ZCLOCKID_AUTH_DIR", "/run/zclockid"))
    try:
        p.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(p, 0o700)
        except Exception:
            pass
    except Exception:
        fallback = Path(tempfile.gettempdir()) / "zclockid-auth"
        fallback.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(fallback, 0o700)
        except Exception:
            pass
        return fallback
    return p


def cleanup_stale_auth_files() -> int:
    """Deletes stale zclock_auth_* files in auth runtime directory at API startup."""
    target_dir = get_auth_runtime_dir()
    count = 0
    try:
        if target_dir.exists():
            for f in target_dir.glob("zclock_auth_*"):
                try:
                    f.unlink(missing_ok=True)
                    count += 1
                except Exception as e:
                    logger.warning("Failed to remove stale auth file %s: %s", f, e)
    except Exception as e:
        logger.warning("Error cleaning stale auth files in %s: %s", target_dir, e)
    return count


@contextmanager
def temporary_auth_file(username: Optional[str] = None, password: Optional[str] = None):
    """
    Context manager creating a temporary 0600 file holding credentials for samba-tool -A.
    Created inside root-only directory (mode 0700), and automatically unlinked on exit.
    """
    if username is None or password is None:
        admin_u, admin_p = get_ad_creds()
        username = username or admin_u
        password = password or admin_p

    target_dir = get_auth_runtime_dir()
    fd, path = tempfile.mkstemp(prefix="zclock_auth_", suffix=".tmp", dir=str(target_dir))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"username = {username}\npassword = {password}\n")
        yield path
    finally:
        if os.path.exists(path):
            try:
                os.unlink(path)
            except Exception:
                pass


def run_samba_tool_authenticated(args: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """
    Executes a samba-tool command by passing domain credentials strictly via a 0600
    temporary auth file (-A <path>) in root-only runtime directory, never as command line arguments.
    """
    with temporary_auth_file() as authfile:
        cmd = ["samba-tool"] + list(args) + [f"-A{authfile}"]
        return run_cmd(cmd, timeout=timeout)


def samdb_newuser(
    username: str,
    password: str,
    given_name: Optional[str] = None,
    surname: Optional[str] = None,
    email: Optional[str] = None,
    mobile: Optional[str] = None,
    department: Optional[str] = None,
    description: Optional[str] = None,
    force_password_change: bool = False
) -> None:
    """Creates a new Active Directory user in-process via SamDB."""
    db = get_samdb()
    db.newuser(
        username=username,
        password=password,
        force_password_change_at_next_login_req=force_password_change,
        useusernameascn=True,
        surname=surname,
        givenname=given_name,
        mailaddress=email,
        telephonenumber=mobile,
        department=department,
        description=description
    )


def samdb_setpassword(username: str, new_password: str, force_change_at_next_login: bool = False) -> None:
    """Sets a user's password in Active Directory in-process via SamDB with LDAP filter escaping."""
    db = get_samdb()
    clean_u = escape_ldap_filter_value(username)
    db.setpassword(
        search_filter=f"(sAMAccountName={clean_u})",
        password=new_password,
        force_change_at_next_login=force_change_at_next_login,
        username=username
    )


def samdb_setexpiry(username: str, days: Optional[int] = None, noexpiry: bool = False) -> None:
    """Sets account/password expiry in Active Directory in-process via SamDB with LDAP filter escaping."""
    db = get_samdb()
    clean_u = escape_ldap_filter_value(username)
    if noexpiry:
        db.setexpiry(f"(sAMAccountName={clean_u})", 0, no_expiry_req=True)
    else:
        exp_sec = (days or 0) * 86400
        db.setexpiry(f"(sAMAccountName={clean_u})", exp_sec, no_expiry_req=False)


def samdb_enable_account(username: str) -> None:
    """Enables a user account in Active Directory in-process via SamDB with LDAP filter escaping."""
    db = get_samdb()
    clean_u = escape_ldap_filter_value(username)
    db.enable_account(f"(sAMAccountName={clean_u})")


def samdb_disable_account(username: str) -> None:
    """Disables a user account in Active Directory in-process via SamDB with LDAP filter escaping."""
    db = get_samdb()
    clean_u = escape_ldap_filter_value(username)
    db.disable_account(f"(sAMAccountName={clean_u})")


def samdb_deleteuser(username: str) -> None:
    """Deletes a user account from Active Directory in-process via SamDB."""
    db = get_samdb()
    db.deleteuser(username)


def samdb_newgroup(group_name: str, description: Optional[str] = None) -> None:
    """Creates a new security group in Active Directory in-process via SamDB."""
    db = get_samdb()
    db.newgroup(groupname=group_name, description=description)


def samdb_deletegroup(group_name: str) -> None:
    """Deletes a security group from Active Directory in-process via SamDB."""
    db = get_samdb()
    db.deletegroup(groupname=group_name)


def samdb_add_group_member(group_name: str, username: str) -> None:
    """Adds a member to an Active Directory security group in-process via SamDB."""
    db = get_samdb()
    db.add_remove_group_members(group=group_name, members=[username], add_members_operation=True)


def samdb_remove_group_member(group_name: str, username: str) -> None:
    """Removes a member from an Active Directory security group in-process via SamDB."""
    db = get_samdb()
    db.add_remove_group_members(group=group_name, members=[username], add_members_operation=False)
