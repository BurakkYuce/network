from datetime import UTC, datetime
from typing import Any

from netauto.state.models.v1 import (
    ACL,
    AAAConfig,
    AAAMethodList,
    AAAServer,
    ACLEntry,
    BootConfig,
    DeviceStateV1,
    Interface,
    LineConfig,
    LocalUser,
    LoggingConfig,
    LoggingHost,
    SNMPCommunity,
    SNMPConfig,
    SNMPHost,
)


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


def normalize_aaa(parsed_config: dict[str, Any]) -> AAAConfig | None:
    """Map Genie ``aaa`` parse block to canonical AAAConfig."""
    aaa_raw = parsed_config.get("aaa")
    if not aaa_raw:
        return None
    servers: list[AAAServer] = []
    for s in aaa_raw.get("servers") or []:
        servers.append(
            AAAServer(
                address=s["address"],
                type=s.get("type", "tacacs+"),
                key_set=bool(s.get("key") or s.get("key_set")),
            )
        )
    method_lists: list[AAAMethodList] = []
    for ml in aaa_raw.get("method_lists") or []:
        method_lists.append(
            AAAMethodList(
                name=ml["name"],
                type=ml["type"],
                methods=list(ml.get("methods") or []),
            )
        )
    return AAAConfig(servers=servers, method_lists=method_lists)


def normalize_logging(parsed_config: dict[str, Any]) -> LoggingConfig | None:
    """Map Genie ``logging`` block to canonical LoggingConfig."""
    log_raw = parsed_config.get("logging")
    if log_raw is None:
        return None
    hosts: list[LoggingHost] = []
    for h in log_raw.get("hosts") or []:
        hosts.append(
            LoggingHost(
                host=h["host"],
                transport=h.get("transport", "udp"),
                port=int(h.get("port", 514)),
                severity=int(h.get("severity", 6)),
                vrf=h.get("vrf"),
            )
        )
    return LoggingConfig(
        enabled=bool(log_raw.get("enabled", True)),
        hosts=hosts,
        facility=log_raw.get("facility"),
        buffered_size=log_raw.get("buffered_size"),
    )


def normalize_snmp(parsed_config: dict[str, Any]) -> SNMPConfig | None:
    """Map Genie ``snmp_server`` block to canonical SNMPConfig."""
    snmp_raw = parsed_config.get("snmp_server") or parsed_config.get("snmp")
    if snmp_raw is None:
        return None
    communities: list[SNMPCommunity] = []
    for c in snmp_raw.get("communities") or []:
        communities.append(
            SNMPCommunity(
                name=c["name"],
                access=c.get("access", "RO"),
                acl=c.get("acl"),
            )
        )
    hosts: list[SNMPHost] = []
    for h in snmp_raw.get("hosts") or []:
        hosts.append(
            SNMPHost(
                host=h["host"],
                community=h.get("community"),
                traps=bool(h.get("traps", True)),
                version=str(h.get("version", "2c")),  # type: ignore[arg-type]
            )
        )
    return SNMPConfig(communities=communities, hosts=hosts)


def normalize_lines(parsed_config: dict[str, Any]) -> dict[str, LineConfig]:
    """Map Genie ``line`` block to canonical Line dict (key = range string)."""
    lines: dict[str, LineConfig] = {}
    for line in parsed_config.get("line") or []:
        line_range = line["range"]
        lines[line_range] = LineConfig(
            range=line_range,
            transport_input=list(line.get("transport_input") or []),
            access_class_in=line.get("access_class_in"),
            access_class_out=line.get("access_class_out"),
            exec_timeout_seconds=line.get("exec_timeout_seconds"),
            privilege=line.get("privilege"),
        )
    return lines


def normalize_boot(parsed_config: dict[str, Any]) -> BootConfig | None:
    """Map Genie boot/platform parse block to canonical BootConfig."""
    boot_raw = parsed_config.get("boot")
    if boot_raw is None:
        return None
    return BootConfig(
        boot_system=list(boot_raw.get("boot_system") or []),
        confreg=boot_raw.get("confreg"),
        rommon_vars=dict(boot_raw.get("rommon_vars") or {}),
    )


def normalize_ios_xe(
    *,
    hostname: str,
    interfaces: dict[str, Any] | None = None,
    parsed_config: dict[str, Any] | None = None,
    captured_at: datetime | None = None,
) -> DeviceStateV1:
    """Compose a DeviceStateV1 from Genie outputs for an IOS-XE device."""
    cfg = parsed_config or {}
    return DeviceStateV1(
        hostname=hostname,
        platform="ios-xe",
        captured_at=captured_at or datetime.now(UTC),
        interfaces=normalize_interfaces(interfaces or {}),
        users=normalize_users(cfg),
        acls=normalize_acls(cfg),
        aaa=normalize_aaa(cfg),
        logging=normalize_logging(cfg),
        snmp=normalize_snmp(cfg),
        lines=normalize_lines(cfg),
        boot=normalize_boot(cfg),
    )
