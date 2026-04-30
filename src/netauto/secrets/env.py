import os
from collections.abc import Mapping

from pydantic import SecretStr

from netauto.secrets.base import (
    CredentialKind,
    DeviceCredentials,
    SecretsNotFoundError,
)


def _normalize(hostname: str) -> str:
    return hostname.upper().replace("-", "_").replace(".", "_")


class EnvSecretsProvider:
    """Read credentials from environment variables.

    Lookup order (first match wins):
      NETAUTO_<HOST>_<KIND>_USERNAME / _PASSWORD
      NETAUTO_DEFAULT_<KIND>_USERNAME / _PASSWORD

    HOST is the device hostname uppercased with '-' and '.' replaced by '_'.
    KIND is 'RO' or 'RW'.

    For demo only: prefer Vault (or any centralised secrets store) for any
    multi-tenant or production deployment.
    """

    def __init__(self, env: Mapping[str, str] | None = None) -> None:
        self._env: Mapping[str, str] = env if env is not None else os.environ

    def get_device_credentials(
        self, device_hostname: str, kind: CredentialKind
    ) -> DeviceCredentials:
        host = _normalize(device_hostname)
        kstr = kind.value.upper()
        user_keys = [f"NETAUTO_{host}_{kstr}_USERNAME", f"NETAUTO_DEFAULT_{kstr}_USERNAME"]
        pass_keys = [f"NETAUTO_{host}_{kstr}_PASSWORD", f"NETAUTO_DEFAULT_{kstr}_PASSWORD"]

        username = next((self._env[k] for k in user_keys if k in self._env), None)
        if username is None:
            raise SecretsNotFoundError(
                f"no {kind.value} credentials for {device_hostname}; set one of {user_keys}"
            )
        password = next((self._env[k] for k in pass_keys if k in self._env), None)
        return DeviceCredentials(
            username=username,
            password=SecretStr(password) if password else None,
            kind=kind,
        )
