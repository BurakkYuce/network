from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from netauto.inventory.facts import Platform


class Interface(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str | None = None
    enabled: bool = True
    ipv4_addresses: list[str] = Field(default_factory=list)
    mtu: int | None = None
    vrf: str | None = None
    acl_in: str | None = None
    acl_out: str | None = None


class LocalUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    privilege: int = Field(default=1, ge=0, le=15)
    password_set: bool = False
    ssh_key_set: bool = False


class ACLEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=1)
    action: Literal["permit", "deny"]
    proto: str
    src: str
    dst: str
    src_port: str | None = None
    dst_port: str | None = None
    log: bool = False


class ACL(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: Literal["standard", "extended"] = "extended"
    entries: list[ACLEntry] = Field(default_factory=list)


class AAAServer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    type: Literal["tacacs+", "radius", "ldap"] = "tacacs+"
    key_set: bool = False  # password indicator only — never store the key


class AAAMethodList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: Literal["authentication", "authorization", "accounting"]
    methods: list[str] = Field(default_factory=list)  # e.g. ["group tacacs+", "local"]


class AAAConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    servers: list[AAAServer] = Field(default_factory=list)
    method_lists: list[AAAMethodList] = Field(default_factory=list)


class LoggingHost(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    transport: Literal["udp", "tcp"] = "udp"
    port: int = 514
    severity: int = Field(default=6, ge=0, le=7)
    vrf: str | None = None


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    hosts: list[LoggingHost] = Field(default_factory=list)
    facility: str | None = None
    buffered_size: int | None = None


class SNMPCommunity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    access: Literal["RO", "RW"] = "RO"
    acl: str | None = None


class SNMPHost(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    community: str | None = None
    traps: bool = True
    version: Literal["1", "2c", "3"] = "2c"


class SNMPConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    communities: list[SNMPCommunity] = Field(default_factory=list)
    hosts: list[SNMPHost] = Field(default_factory=list)


class LineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    range: str  # "vty 0 4", "console 0", "aux 0"
    transport_input: list[str] = Field(default_factory=list)  # ["ssh"], ["ssh","telnet"]
    access_class_in: str | None = None
    access_class_out: str | None = None
    exec_timeout_seconds: int | None = None
    privilege: int | None = Field(default=None, ge=0, le=15)


class BootConfig(BaseModel):
    """Boot path / ROMmon / config-register state.

    Used by detection rules around T1542 (Pre-OS Boot) and T1601 (Modify
    System Image). Names align with the detection rule schema.
    """

    model_config = ConfigDict(extra="forbid")

    boot_system: list[str] = Field(default_factory=list)  # e.g. ["flash:img.bin"]
    confreg: str | None = None  # e.g. "0x2102" (normal) vs "0x2142" (config bypass)
    rommon_vars: dict[str, str] = Field(default_factory=dict)


class DeviceStateV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    hostname: str
    platform: Platform
    captured_at: datetime
    interfaces: dict[str, Interface] = Field(default_factory=dict)
    users: dict[str, LocalUser] = Field(default_factory=dict)
    acls: dict[str, ACL] = Field(default_factory=dict)
    aaa: AAAConfig | None = None
    logging: LoggingConfig | None = None
    snmp: SNMPConfig | None = None
    lines: dict[str, LineConfig] = Field(default_factory=dict)
    boot: BootConfig | None = None
