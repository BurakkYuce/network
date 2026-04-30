"""HashiCorp Vault secrets provider — Faz 1.5 stub.

The interface lands now so collector / response engines can depend on
``SecretsProvider`` without coupling to env-vars. The wire-level integration
(HVAC client, AppRole bootstrap, KV v2 reads, lease handling for short-TTL
rw credentials) is deferred to Faz 8 when Vault is in scope.
"""

from typing import Any

from netauto.secrets.base import (
    CredentialKind,
    DeviceCredentials,
    SecretsNotFoundError,
)


class VaultSecretsProvider:
    """Stub — raises until a real Vault client is configured (Faz 8+).

    Construction takes an optional ``client`` so unit tests can pass a mock
    object that responds to the same calls a real ``hvac.Client`` would.
    """

    def __init__(
        self,
        *,
        client: Any | None = None,
        mount_point: str = "netauto",
    ) -> None:
        self.client = client
        self.mount_point = mount_point

    def get_device_credentials(
        self, device_hostname: str, kind: CredentialKind
    ) -> DeviceCredentials:
        if self.client is None:
            raise SecretsNotFoundError(
                "Vault client not configured. For demo use EnvSecretsProvider; "
                "full Vault integration lands in faz 8."
            )
        # Path layout: <mount>/devices/<host>/<kind>
        path = f"devices/{device_hostname}/{kind.value}"
        # Generic call shape compatible with hvac.Client.secrets.kv.v2 API
        result = self.client.secrets.kv.v2.read_secret_version(
            path=path, mount_point=self.mount_point
        )
        data = result["data"]["data"]
        from pydantic import SecretStr

        return DeviceCredentials(
            username=data["username"],
            password=SecretStr(data["password"]) if data.get("password") else None,
            kind=kind,
        )
