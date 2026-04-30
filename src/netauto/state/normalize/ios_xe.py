from datetime import UTC, datetime
from typing import Any

from netauto.state.models.v1 import ACL, ACLEntry, DeviceStateV1, Interface, LocalUser


def normalize_interfaces(genie_intf: dict[str, Any]) -> dict[str, Interface]:
    """Map Genie ``learn('interface')`` output to canonical Interface dict."""
    result: dict[str, Interface] = {}
    for name, data in genie_intf.items():
        ipv4_keys = list((data.get("ipv4") or {}).keys())
        access_group = data.get("access_group") or {}
        result[name] = Interface(
            name=name,
            description=data.get("description"),
            enabled=data.get("enabled", True),
            ipv4_addresses=ipv4_keys,
            mtu=data.get("mtu"),
            vrf=data.get("vrf"),
            acl_in=access_group.get("in"),
            acl_out=access_group.get("out"),
        )
    return result


def normalize_users(parsed_config: dict[str, Any]) -> dict[str, LocalUser]:
    """Map Genie running-config ``username`` block to LocalUser dict."""
    users: dict[str, LocalUser] = {}
    for name, data in (parsed_config.get("username") or {}).items():
        users[name] = LocalUser(
            name=name,
            privilege=int(data.get("privilege", 1)),
            password_set=bool(data.get("secret") or data.get("password")),
            ssh_key_set=bool(data.get("ssh_key")),
        )
    return users


def normalize_acls(parsed_config: dict[str, Any]) -> dict[str, ACL]:
    """Map Genie ``ip_access_list`` parse output to canonical ACL dict."""
    acls: dict[str, ACL] = {}
    for acl_name, acl_data in (parsed_config.get("ip_access_list") or {}).items():
        entries: list[ACLEntry] = []
        for seq_key, e in (acl_data.get("entries") or {}).items():
            seq = int(seq_key) if str(seq_key).isdigit() else (len(entries) + 1) * 10
            entries.append(
                ACLEntry(
                    seq=seq,
                    action=e.get("action", "permit"),
                    proto=e.get("protocol", "ip"),
                    src=e.get("src", "any"),
                    dst=e.get("dst", "any"),
                    src_port=e.get("src_port"),
                    dst_port=e.get("dst_port"),
                    log=bool(e.get("log")),
                )
            )
        entries.sort(key=lambda x: x.seq)
        acls[acl_name] = ACL(
            name=acl_name,
            type=acl_data.get("type", "extended"),
            entries=entries,
        )
    return acls


def normalize_ios_xe(
    *,
    hostname: str,
    interfaces: dict[str, Any] | None = None,
    parsed_config: dict[str, Any] | None = None,
    captured_at: datetime | None = None,
) -> DeviceStateV1:
    """Compose a DeviceStateV1 from Genie outputs for an IOS-XE device."""
    return DeviceStateV1(
        hostname=hostname,
        platform="ios-xe",
        captured_at=captured_at or datetime.now(UTC),
        interfaces=normalize_interfaces(interfaces or {}),
        users=normalize_users(parsed_config or {}),
        acls=normalize_acls(parsed_config or {}),
    )
