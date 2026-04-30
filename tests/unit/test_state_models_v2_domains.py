"""Unit tests for the new state-model domains added in faz 2:
AAA, logging, SNMP, lines, boot."""

import pytest
from pydantic import ValidationError

from netauto.state.models.v1 import (
    AAAConfig,
    AAAMethodList,
    AAAServer,
    BootConfig,
    LineConfig,
    LoggingConfig,
    LoggingHost,
    SNMPCommunity,
    SNMPConfig,
    SNMPHost,
)


def test_aaa_server_default_type() -> None:
    s = AAAServer(address="10.0.0.1")
    assert s.type == "tacacs+"
    assert s.key_set is False


def test_aaa_server_invalid_type() -> None:
    with pytest.raises(ValidationError):
        AAAServer(address="10.0.0.1", type="kerberos")  # type: ignore[arg-type]


def test_aaa_method_list_invalid_type() -> None:
    with pytest.raises(ValidationError):
        AAAMethodList(name="default", type="auditing")  # type: ignore[arg-type]


def test_aaa_config_holds_lists() -> None:
    cfg = AAAConfig(
        servers=[AAAServer(address="10.0.0.1"), AAAServer(address="10.0.0.2")],
        method_lists=[AAAMethodList(name="default", type="authentication")],
    )
    assert len(cfg.servers) == 2
    assert cfg.method_lists[0].type == "authentication"


def test_logging_host_severity_range() -> None:
    LoggingHost(host="10.0.0.1", severity=6)
    with pytest.raises(ValidationError):
        LoggingHost(host="10.0.0.1", severity=8)
    with pytest.raises(ValidationError):
        LoggingHost(host="10.0.0.1", severity=-1)


def test_logging_host_default_transport_and_port() -> None:
    h = LoggingHost(host="10.0.0.1")
    assert h.transport == "udp"
    assert h.port == 514
    assert h.severity == 6


def test_logging_config_defaults() -> None:
    c = LoggingConfig()
    assert c.enabled is True
    assert c.hosts == []
    assert c.facility is None


def test_snmp_community_defaults() -> None:
    c = SNMPCommunity(name="public")
    assert c.access == "RO"
    assert c.acl is None


def test_snmp_community_invalid_access() -> None:
    with pytest.raises(ValidationError):
        SNMPCommunity(name="public", access="ALL")  # type: ignore[arg-type]


def test_snmp_host_defaults() -> None:
    h = SNMPHost(host="10.0.0.1")
    assert h.version == "2c"
    assert h.traps is True


@pytest.mark.parametrize("version", ["1", "2c", "3"])
def test_snmp_host_valid_versions(version: str) -> None:
    SNMPHost(host="10.0.0.1", version=version)  # type: ignore[arg-type]


def test_snmp_host_invalid_version() -> None:
    with pytest.raises(ValidationError):
        SNMPHost(host="10.0.0.1", version="4")  # type: ignore[arg-type]


def test_snmp_config_aggregates() -> None:
    c = SNMPConfig(
        communities=[SNMPCommunity(name="ro"), SNMPCommunity(name="rw", access="RW")],
        hosts=[SNMPHost(host="10.0.0.1")],
    )
    assert len(c.communities) == 2
    assert c.communities[1].access == "RW"


def test_line_config_minimal() -> None:
    line = LineConfig(range="vty 0 4")
    assert line.transport_input == []
    assert line.access_class_in is None


def test_line_config_with_acl_and_transport() -> None:
    line = LineConfig(
        range="vty 0 4",
        transport_input=["ssh"],
        access_class_in="MGMT-IN",
        exec_timeout_seconds=600,
    )
    assert line.access_class_in == "MGMT-IN"
    assert line.transport_input == ["ssh"]


def test_line_config_invalid_privilege() -> None:
    with pytest.raises(ValidationError):
        LineConfig(range="vty 0 4", privilege=16)


def test_boot_config_defaults() -> None:
    b = BootConfig()
    assert b.boot_system == []
    assert b.confreg is None
    assert b.rommon_vars == {}


def test_boot_config_with_attack_indicators() -> None:
    """confreg=0x2142 + rommon_vars are T1542.003 indicators."""
    b = BootConfig(
        boot_system=["tftp:malicious.bin"],
        confreg="0x2142",
        rommon_vars={"BOOT": "tftp://attacker/x.bin"},
    )
    assert b.confreg == "0x2142"
    assert "tftp" in b.boot_system[0]
    assert b.rommon_vars["BOOT"].startswith("tftp")


def test_extra_field_forbidden_on_aaa_server() -> None:
    with pytest.raises(ValidationError):
        AAAServer(address="x", unknown="x")  # type: ignore[call-arg]


def test_extra_field_forbidden_on_boot() -> None:
    with pytest.raises(ValidationError):
        BootConfig(unknown_field="x")  # type: ignore[call-arg]
