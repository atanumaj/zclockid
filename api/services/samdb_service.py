"""
api/services/samdb_service.py: In-process Samba Active Directory operations using SamDB.
Eliminates passing passwords and secrets on command line arguments.
"""
import os
import tempfile
import logging
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager

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


class MockSamDB:
    """Mock SamDB for testing or environments where python3-samba is not installed."""
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
        if u and u in self.users:
            self.users[u]["password"] = password

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


def get_samdb():
    """Returns an initialized SamDB instance or MockSamDB if native bindings unavailable."""
    if not HAS_SAMBA_BINDINGS:
        return _global_mock_samdb
    try:
        lp = LoadParm()
        if os.path.exists(str(SMB_CONF_FILE)):
            lp.load(str(SMB_CONF_FILE))
        return SamDB(url=str(SAMBA_LDB_PATH), session_info=system_session(), lp=lp)
    except Exception as e:
        logger.warning("Failed to open SamDB at %s: %s", SAMBA_LDB_PATH, e)
        return _global_mock_samdb


@contextmanager
def temporary_auth_file(username: Optional[str] = None, password: Optional[str] = None):
    """
    Context manager creating a temporary 0600 file holding credentials for samba-tool -A.
    Automatically deleted on exit.
    """
    if username is None or password is None:
        admin_u, admin_p = get_ad_creds()
        username = username or admin_u
        password = password or admin_p

    fd, path = tempfile.mkstemp(prefix="zclock_auth_", suffix=".tmp")
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
    temporary auth file (-A <path>), never as command line arguments.
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
    """Sets a user's password in Active Directory in-process via SamDB."""
    db = get_samdb()
    db.setpassword(
        search_filter=f"(sAMAccountName={username})",
        password=new_password,
        force_change_at_next_login=force_change_at_next_login,
        username=username
    )


def samdb_setexpiry(username: str, days: Optional[int] = None, noexpiry: bool = False) -> None:
    """Sets account/password expiry in Active Directory in-process via SamDB."""
    db = get_samdb()
    if noexpiry:
        db.setexpiry(f"(sAMAccountName={username})", 0, no_expiry_req=True)
    else:
        exp_sec = (days or 0) * 86400
        db.setexpiry(f"(sAMAccountName={username})", exp_sec, no_expiry_req=False)


def samdb_enable_account(username: str) -> None:
    """Enables a user account in Active Directory in-process via SamDB."""
    db = get_samdb()
    db.enable_account(f"(sAMAccountName={username})")


def samdb_disable_account(username: str) -> None:
    """Disables a user account in Active Directory in-process via SamDB."""
    db = get_samdb()
    db.disable_account(f"(sAMAccountName={username})")


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
