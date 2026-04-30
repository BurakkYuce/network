from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from netauto.state.models.v1 import (
    ACL,
    ACLEntry,
    DeviceStateV1,
    Interface,
    LocalUser,
)


def test_interface_minimal() -> None:
    i = Interface(name="GigabitEthernet0/0")
    assert i.name == "GigabitEthernet0/0"
    assert i.enabled is True
    assert i.ipv4_addresses == []
    assert i.acl_in is None


def test_interface_full() -> None:
    i = Interface(
        name="Gi0/1",
        description="uplink",
        enabled=False,
        ipv4_addresses=["10.0.0.1/24"],
        mtu=1500,
        vrf="MGMT",
        acl_in="MGMT-IN",
        acl_out="MGMT-OUT",
    )
    assert i.vrf == "MGMT"
    assert i.acl_in == "MGMT-IN"


def test_interface_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        Interface(name="Gi0/0", unknown_field="x")  # type: ignore[call-arg]


@pytest.mark.parametrize("priv", [0, 1, 15])
def test_local_user_valid_priv(priv: int) -> None:
    u = LocalUser(name="admin", privilege=priv)
    assert u.privilege == priv


@pytest.mark.parametrize("priv", [-1, 16, 100])
def test_local_user_invalid_priv(priv: int) -> None:
    with pytest.raises(ValidationError):
        LocalUser(name="admin", privilege=priv)


def test_acl_entry_basic() -> None:
    e = ACLEntry(seq=10, action="permit", proto="tcp", src="any", dst="any", dst_port="22")
    assert e.action == "permit"
    assert e.dst_port == "22"


def test_acl_entry_invalid_action() -> None:
    with pytest.raises(ValidationError):
        ACLEntry(seq=10, action="allow", proto="ip", src="any", dst="any")  # type: ignore[arg-type]


def test_acl_entry_seq_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        ACLEntry(seq=0, action="permit", proto="ip", src="any", dst="any")


def test_acl_with_entries() -> None:
    a = ACL(
        name="EDGE-IN",
        entries=[
            ACLEntry(seq=10, action="permit", proto="tcp", src="any", dst="any", dst_port="443"),
            ACLEntry(seq=20, action="deny", proto="ip", src="any", dst="any", log=True),
        ],
    )
    assert len(a.entries) == 2
    assert a.type == "extended"


def test_device_state_v1_minimal() -> None:
    s = DeviceStateV1(
        hostname="r1",
        platform="ios-xe",
        captured_at=datetime.now(UTC),
    )
    assert s.schema_version == 1
    assert s.interfaces == {}
    assert s.users == {}
    assert s.acls == {}


def test_device_state_v1_full() -> None:
    s = DeviceStateV1(
        hostname="r1",
        platform="ios-xe",
        captured_at=datetime.now(UTC),
        interfaces={"Gi0/0": Interface(name="Gi0/0")},
        users={"admin": LocalUser(name="admin", privilege=15, password_set=True)},
        acls={
            "EDGE-IN": ACL(
                name="EDGE-IN",
                entries=[
                    ACLEntry(seq=10, action="permit", proto="tcp", src="any", dst="any"),
                ],
            ),
        },
    )
    assert s.users["admin"].privilege == 15
    assert s.acls["EDGE-IN"].entries[0].seq == 10


def test_device_state_v1_schema_version_pinned() -> None:
    with pytest.raises(ValidationError):
        DeviceStateV1(
            schema_version=2,  # type: ignore[arg-type]
            hostname="r1",
            platform="ios-xe",
            captured_at=datetime.now(UTC),
        )


def test_device_state_v1_round_trip_json() -> None:
    s1 = DeviceStateV1(
        hostname="r1",
        platform="ios-xe",
        captured_at=datetime(2026, 4, 30, 13, 0, 0, tzinfo=UTC),
        interfaces={"Gi0/0": Interface(name="Gi0/0", description="lan")},
    )
    payload = s1.model_dump(mode="json")
    s2 = DeviceStateV1.model_validate(payload)
    assert s2 == s1
