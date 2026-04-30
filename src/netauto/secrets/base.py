from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, SecretStr


class CredentialKind(StrEnum):
    """Operational scope of a credential.

    READ_ONLY is for the continuous state collector — never used for config
    push. READ_WRITE is for response actions (auto-rollback, ACL push) and
    must be issued on demand with short TTL when sourced from Vault.
    """

    READ_ONLY = "ro"
    READ_WRITE = "rw"


class DeviceCredentials(BaseModel):
    """A single set of credentials scoped to one device + one kind."""

    model_config = ConfigDict(extra="forbid")

    username: str
    password: SecretStr | None = None
    ssh_key_path: Path | None = None
    enable_password: SecretStr | None = None
    kind: CredentialKind


class SecretsNotFoundError(Exception):
    """Raised when no credentials are available for a (device, kind) pair."""


@runtime_checkable
class SecretsProvider(Protocol):
    """Read-only interface for fetching device credentials.

    Implementations enforce per-device isolation (no shared credentials
    across the fleet) and ro/rw split (rw_user must NEVER be returned to
    a caller that asked for ro).
    """

    def get_device_credentials(
        self, device_hostname: str, kind: CredentialKind
    ) -> DeviceCredentials:
        """Return credentials for ``(device_hostname, kind)``.

        Raises SecretsNotFoundError if no matching credentials exist.
        """
        ...
