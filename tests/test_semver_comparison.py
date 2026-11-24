import pytest
from api.services.system_service import parse_semver, is_newer_version, is_downgrade_version

def test_parse_semver_padding():
    assert parse_semver("1.5.4") == (1, 5, 4, 0)
    assert parse_semver("v1.5.4") == (1, 5, 4, 0)
    assert parse_semver("1.5.4.1") == (1, 5, 4, 1)
    assert parse_semver("v1.5.4.1") == (1, 5, 4, 1)
    assert parse_semver("1.5.4.1.2") == (1, 5, 4, 1, 2)
    assert parse_semver("2") == (2, 0, 0, 0)

def test_is_newer_version_standard():
    assert is_newer_version("1.5.5", "1.5.4") is True
    assert is_newer_version("1.6.0", "1.5.9") is True
    assert is_newer_version("2.0.0", "1.99.99") is True
    assert is_newer_version("1.5.4", "1.5.5") is False
    assert is_newer_version("1.5.4", "1.5.4") is False

def test_is_newer_version_four_segment_hotfix():
    # Crucial regression test: 1.5.4.1 MUST be recognized as newer than 1.5.4
    assert is_newer_version("1.5.4.1", "1.5.4") is True
    assert is_newer_version("1.5.4.2", "1.5.4.1") is True
    assert is_newer_version("1.5.5", "1.5.4.1") is True
    assert is_newer_version("1.5.4", "1.5.4.1") is False
    assert is_newer_version("1.5.4.1", "1.5.4.1") is False

def test_is_downgrade_version():
    assert is_downgrade_version("1.5.4", "1.5.5") is True
    assert is_downgrade_version("1.5.4", "1.5.4.1") is True
    assert is_downgrade_version("1.5.4.1", "1.5.4") is False
    assert is_downgrade_version("1.5.4.1", "1.5.4.1") is False
