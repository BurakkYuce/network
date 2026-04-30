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


class DeviceStateV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    hostname: str
    platform: Platform
    captured_at: datetime
    interfaces: dict[str, Interface] = Field(default_factory=dict)
    users: dict[str, LocalUser] = Field(default_factory=dict)
    acls: dict[str, ACL] = Field(default_factory=dict)
