"""
api/core/archive_security.py: Hardened archive extraction for TAR and ZIP formats.
Prevents directory traversal, symlink escapes, device files, and archive bombs.
"""

import os
import tarfile
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from fastapi import HTTPException, status

# Default resource caps
DEFAULT_MAX_ARCHIVE_FILES = 10_000
DEFAULT_MAX_ARCHIVE_SIZE_BYTES = 500 * 1024 * 1024  # 500 MB


class ArchiveSecurityError(HTTPException):
    """Raised when an archive contains insecure path traversal, symlink escape, or exceeds limits."""
    def __init__(self, detail: str = "Archive contains insecure paths or exceeds limits"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _is_path_safe(base_dir: Path, target_path: Path) -> bool:
    """Checks whether target_path resides strictly within base_dir."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return resolved_target == resolved_base or resolved_base in resolved_target.parents
    except Exception:
        return False


def validate_tar_archive(
    tar: tarfile.TarFile,
    dest_dir: Path,
    max_files: int = DEFAULT_MAX_ARCHIVE_FILES,
    max_size: int = DEFAULT_MAX_ARCHIVE_SIZE_BYTES
) -> None:
    """
    Validates all members of a tarfile before extraction:
    - Rejects absolute paths and path traversal (..)
    - Rejects device, FIFO, or socket files
    - Rejects symlinks or hardlinks pointing outside dest_dir
    - Enforces file count and uncompressed size caps
    """
    dest_resolved = dest_dir.resolve()
    total_files = 0
    total_size = 0

    for member in tar.getmembers():
        total_files += 1
        if total_files > max_files:
            raise ArchiveSecurityError(f"Archive exceeds maximum allowed file count ({max_files}).")

        total_size += member.size
        if total_size > max_size:
            raise ArchiveSecurityError(f"Archive exceeds maximum allowed uncompressed size ({max_size} bytes).")

        name = member.name
        # Reject absolute paths or Windows drive letters
        if os.path.isabs(name) or name.startswith("/") or name.startswith("\\") or (len(name) > 1 and name[1] == ":"):
            raise ArchiveSecurityError(f"Archive member has an absolute path: '{name}'")

        # Reject path traversal tokens
        parts = Path(name).parts
        if ".." in parts:
            raise ArchiveSecurityError(f"Archive member contains directory traversal '..': '{name}'")

        target_path = (dest_dir / name)
        # Check target resolution
        if not _is_path_safe(dest_resolved, target_path):
            raise ArchiveSecurityError(f"Archive member resolves outside target directory: '{name}'")

        # Reject device files and special nodes
        if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
            raise ArchiveSecurityError(f"Archive contains unsupported special/device file: '{name}'")

        # Validate symlinks and hardlinks
        if member.issym() or member.islnk():
            linkname = member.linkname
            if os.path.isabs(linkname) or linkname.startswith("/") or linkname.startswith("\\"):
                raise ArchiveSecurityError(f"Archive link points to absolute path: '{name}' -> '{linkname}'")

            member_parent = (dest_dir / Path(name).parent)
            link_target = (member_parent / linkname)
            if not _is_path_safe(dest_resolved, link_target):
                raise ArchiveSecurityError(f"Archive symlink points outside staging directory: '{name}' -> '{linkname}'")


def safe_extract_tar(
    tar: tarfile.TarFile,
    dest_dir: Path,
    max_files: int = DEFAULT_MAX_ARCHIVE_FILES,
    max_size: int = DEFAULT_MAX_ARCHIVE_SIZE_BYTES
) -> None:
    """
    Safely extracts tar contents into dest_dir:
    - Pre-validates all members against traversal and escape
    - Uses filter='data' where supported (Python 3.12+)
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    validate_tar_archive(tar, dest_dir, max_files=max_files, max_size=max_size)

    # Use filter='data' on Python 3.12+
    if hasattr(tarfile, "data_filter"):
        tar.extractall(path=dest_dir, filter="data")
    else:
        # On older Python, members have been validated above
        for member in tar.getmembers():
            tar.extract(member, path=dest_dir)


def validate_zip_archive(
    zf: zipfile.ZipFile,
    dest_dir: Path,
    max_files: int = DEFAULT_MAX_ARCHIVE_FILES,
    max_size: int = DEFAULT_MAX_ARCHIVE_SIZE_BYTES
) -> None:
    """
    Validates all members of a zipfile before extraction:
    - Rejects absolute paths and path traversal (..)
    - Verifies filename resolves inside dest_dir
    - Checks symlink escapes
    - Enforces file count and uncompressed size caps
    """
    dest_resolved = dest_dir.resolve()
    total_files = 0
    total_size = 0

    for info in zf.infolist():
        total_files += 1
        if total_files > max_files:
            raise ArchiveSecurityError(f"Archive exceeds maximum allowed file count ({max_files}).")

        total_size += info.file_size
        if total_size > max_size:
            raise ArchiveSecurityError(f"Archive exceeds maximum allowed uncompressed size ({max_size} bytes).")

        name = info.filename
        if os.path.isabs(name) or name.startswith("/") or name.startswith("\\") or (len(name) > 1 and name[1] == ":"):
            raise ArchiveSecurityError(f"Archive member has an absolute path: '{name}'")

        parts = Path(name).parts
        if ".." in parts:
            raise ArchiveSecurityError(f"Archive member contains directory traversal '..': '{name}'")

        target_path = (dest_dir / name)
        if not _is_path_safe(dest_resolved, target_path):
            raise ArchiveSecurityError(f"Archive member resolves outside target directory: '{name}'")

        # Check for symlink entries in ZIP (Unix mode symlink check)
        is_symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
        if is_symlink:
            try:
                link_content = zf.read(info).decode("utf-8", errors="replace").strip()
                if os.path.isabs(link_content) or link_content.startswith("/") or link_content.startswith("\\"):
                    raise ArchiveSecurityError(f"Zip symlink points to absolute path: '{name}' -> '{link_content}'")
                member_parent = (dest_dir / Path(name).parent)
                link_target = (member_parent / link_content)
                if not _is_path_safe(dest_resolved, link_target):
                    raise ArchiveSecurityError(f"Zip symlink points outside staging directory: '{name}' -> '{link_content}'")
            except ArchiveSecurityError:
                raise
            except Exception:
                pass


def safe_extract_zip(
    zf: zipfile.ZipFile,
    dest_dir: Path,
    max_files: int = DEFAULT_MAX_ARCHIVE_FILES,
    max_size: int = DEFAULT_MAX_ARCHIVE_SIZE_BYTES
) -> None:
    """
    Safely extracts zip contents into dest_dir after full validation.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    validate_zip_archive(zf, dest_dir, max_files=max_files, max_size=max_size)
    zf.extractall(dest_dir)
