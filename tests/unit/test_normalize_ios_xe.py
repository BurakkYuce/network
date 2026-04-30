import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from netauto.state.normalize.ios_xe import (
    normalize_aaa,
    normalize_acls,
    normalize_boot,
    normalize_interfaces,
    normalize_ios_xe,
    normalize_lines,
    normalize_logging,
    normalize_snmp,
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
    assert state.aaa is None
    assert state.logging is None
    assert state.snmp is None
    assert state.lines == {}
    assert state.boot is None


def test_normalize_aaa_servers_and_method_lists(cfg_data: dict) -> None:
    aaa = normalize_aaa(cfg_data)
    assert aaa is not None
    assert len(aaa.servers) == 2
    assert aaa.servers[0].address == "10.10.10.5"
    assert aaa.servers[0].type == "tacacs+"
    assert aaa.servers[0].key_set is True
    assert {ml.type for ml in aaa.method_lists} == {"authentication", "authorization"}


def test_normalize_aaa_absent_returns_none() -> None:
    assert normalize_aaa({}) is None


def test_normalize_logging_hosts_and_severity(cfg_data: dict) -> None:
    log = normalize_logging(cfg_data)
    assert log is not None
    assert log.enabled is True
    assert len(log.hosts) == 2
    assert log.hosts[0].host == "10.20.0.10"
    assert log.hosts[1].transport == "tcp"
    assert log.hosts[1].port == 1514
    assert log.facility == "local6"
    assert log.buffered_size == 8192


def test_normalize_logging_absent_returns_none() -> None:
    assert normalize_logging({}) is None


def test_normalize_snmp_communities_and_hosts(cfg_data: dict) -> None:
    snmp = normalize_snmp(cfg_data)
    assert snmp is not None
    assert len(snmp.communities) == 1
    assert snmp.communities[0].name == "ro_public"
    assert snmp.communities[0].access == "RO"
    assert snmp.communities[0].acl == "MGMT-IN"
    assert len(snmp.hosts) == 1
    assert snmp.hosts[0].host == "10.30.0.5"


def test_normalize_snmp_accepts_legacy_key() -> None:
    """Either ``snmp_server`` or ``snmp`` is accepted as the parser key."""
    legacy = {"snmp": {"communities": [{"name": "ro", "access": "RO"}]}}
    snmp = normalize_snmp(legacy)
    assert snmp is not None
    assert snmp.communities[0].name == "ro"


def test_normalize_snmp_absent_returns_none() -> None:
    assert normalize_snmp({}) is None


def test_normalize_lines_keyed_by_range(cfg_data: dict) -> None:
    lines = normalize_lines(cfg_data)
    assert set(lines.keys()) == {"console 0", "vty 0 4", "vty 5 15"}
    vty04 = lines["vty 0 4"]
    assert vty04.transport_input == ["ssh"]
    assert vty04.access_class_in == "MGMT-IN"
    assert vty04.exec_timeout_seconds == 600


def test_normalize_lines_empty_when_absent() -> None:
    assert normalize_lines({}) == {}


def test_normalize_boot_extracts_boot_system_and_confreg(cfg_data: dict) -> None:
    boot = normalize_boot(cfg_data)
    assert boot is not None
    assert boot.boot_system == ["flash:isr4300-universalk9.17.09.04a.SPA.bin"]
    assert boot.confreg == "0x2102"
    assert boot.rommon_vars == {}


def test_normalize_boot_absent_returns_none() -> None:
    assert normalize_boot({}) is None


def test_normalize_ios_xe_full_includes_all_new_domains(intf_data: dict, cfg_data: dict) -> None:
    state = normalize_ios_xe(
        hostname="r1-mock",
        interfaces=intf_data,
        parsed_config=cfg_data,
    )
    assert state.aaa is not None and len(state.aaa.servers) == 2
    assert state.logging is not None and len(state.logging.hosts) == 2
    assert state.snmp is not None and len(state.snmp.communities) == 1
    assert "vty 0 4" in state.lines
    assert state.boot is not None and state.boot.confreg == "0x2102"
