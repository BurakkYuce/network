import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from netauto.state.normalize.ios_xe import (
    normalize_acls,
    normalize_interfaces,
    normalize_ios_xe,
    normalize_users,
)


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "fixtures" / "genie_learn"


@pytest.fixture
def intf_data(fixtures_dir: Path) -> dict:
    return json.loads((fixtures_dir / "r1-mock_interface.json").read_text())


@pytest.fixture
def cfg_data(fixtures_dir: Path) -> dict:
    return json.loads((fixtures_dir / "r1-mock_running_config.json").read_text())


def test_normalize_interfaces_keys_match(intf_data: dict) -> None:
    out = normalize_interfaces(intf_data)
    assert set(out.keys()) == {"GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"}


def test_normalize_interfaces_extracts_acl(intf_data: dict) -> None:
    out = normalize_interfaces(intf_data)
    assert out["GigabitEthernet0/0"].acl_in == "EDGE-IN"
    assert out["GigabitEthernet0/0"].acl_out is None


def test_normalize_interfaces_ipv4_list(intf_data: dict) -> None:
    out = normalize_interfaces(intf_data)
    assert out["GigabitEthernet0/0"].ipv4_addresses == ["10.0.0.1/24"]
    assert out["Loopback0"].ipv4_addresses == ["1.1.1.1/32"]


def test_normalize_interfaces_handles_missing_ipv4() -> None:
    out = normalize_interfaces({"Gi0/0": {"description": "x"}})
    assert out["Gi0/0"].ipv4_addresses == []
    assert out["Gi0/0"].enabled is True  # default


def test_normalize_users_extracts_priv(cfg_data: dict) -> None:
    out = normalize_users(cfg_data)
    assert out["admin"].privilege == 15
    assert out["operator"].privilege == 5
    assert out["monitor"].privilege == 1


def test_normalize_users_password_set_flag(cfg_data: dict) -> None:
    out = normalize_users(cfg_data)
    assert out["admin"].password_set is True
    assert out["operator"].password_set is True
    assert out["monitor"].password_set is False
    assert out["monitor"].ssh_key_set is True


def test_normalize_users_empty_config() -> None:
    assert normalize_users({}) == {}


def test_normalize_acls_count_and_order(cfg_data: dict) -> None:
    out = normalize_acls(cfg_data)
    assert set(out.keys()) == {"EDGE-IN", "MGMT-IN"}
    edge = out["EDGE-IN"]
    assert [e.seq for e in edge.entries] == [10, 20, 30]


def test_normalize_acls_preserves_action_and_log(cfg_data: dict) -> None:
    out = normalize_acls(cfg_data)
    last = out["EDGE-IN"].entries[-1]
    assert last.action == "deny"
    assert last.log is True


def test_normalize_ios_xe_full(intf_data: dict, cfg_data: dict) -> None:
    state = normalize_ios_xe(
        hostname="r1-mock",
        interfaces=intf_data,
        parsed_config=cfg_data,
        captured_at=datetime(2026, 4, 30, 13, 0, 0, tzinfo=UTC),
    )
    assert state.hostname == "r1-mock"
    assert state.platform == "ios-xe"
    assert state.schema_version == 1
    assert "GigabitEthernet0/0" in state.interfaces
    assert "admin" in state.users
    assert "EDGE-IN" in state.acls


def test_normalize_ios_xe_handles_empty_inputs() -> None:
    state = normalize_ios_xe(hostname="r1", captured_at=datetime.now(UTC))
    assert state.interfaces == {}
    assert state.users == {}
    assert state.acls == {}
