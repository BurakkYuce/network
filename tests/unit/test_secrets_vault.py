from typing import Any

import pytest

from netauto.secrets.base import CredentialKind, SecretsNotFoundError
from netauto.secrets.vault import VaultSecretsProvider


class _FakeKvV2:
    def __init__(self, data: dict[str, dict[str, Any]]) -> None:
        self._data = data
        self.last_path: str | None = None
        self.last_mount: str | None = None

    def read_secret_version(self, path: str, mount_point: str) -> dict[str, Any]:
        self.last_path = path
        self.last_mount = mount_point
        if path not in self._data:
            raise KeyError(path)
        return {"data": {"data": self._data[path]}}


class _FakeVaultClient:
    def __init__(self, data: dict[str, dict[str, Any]]) -> None:
        kv_v2 = _FakeKvV2(data)

        class _Kv:
            v2 = kv_v2

        class _Secrets:
            kv = _Kv()

        self.secrets = _Secrets()
        self._kv_v2 = kv_v2


def test_vault_provider_without_client_raises() -> None:
    p = VaultSecretsProvider()
    with pytest.raises(SecretsNotFoundError, match="Vault client not configured"):
        p.get_device_credentials("r1", CredentialKind.READ_ONLY)


def test_vault_provider_with_client_reads_kv_path() -> None:
    client = _FakeVaultClient({"devices/r1-mock/ro": {"username": "ro_user", "password": "ro_pw"}})
    p = VaultSecretsProvider(client=client, mount_point="netauto")
    creds = p.get_device_credentials("r1-mock", CredentialKind.READ_ONLY)
    assert creds.username == "ro_user"
    assert creds.password is not None
    assert creds.password.get_secret_value() == "ro_pw"
    assert client._kv_v2.last_path == "devices/r1-mock/ro"
    assert client._kv_v2.last_mount == "netauto"


def test_vault_provider_uses_separate_path_per_kind() -> None:
    client = _FakeVaultClient(
        {
            "devices/r1/ro": {"username": "ro_user"},
            "devices/r1/rw": {"username": "rw_user", "password": "rw_pw"},
        }
    )
    p = VaultSecretsProvider(client=client)
    ro = p.get_device_credentials("r1", CredentialKind.READ_ONLY)
    rw = p.get_device_credentials("r1", CredentialKind.READ_WRITE)
    assert ro.username == "ro_user"
    assert ro.password is None
    assert rw.username == "rw_user"
    assert rw.password is not None
