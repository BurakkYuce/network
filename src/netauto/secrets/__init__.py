from netauto.secrets.base import (
    CredentialKind,
    DeviceCredentials,
    SecretsNotFoundError,
    SecretsProvider,
)
from netauto.secrets.env import EnvSecretsProvider
from netauto.secrets.vault import VaultSecretsProvider

__all__ = [
    "CredentialKind",
    "DeviceCredentials",
    "EnvSecretsProvider",
    "SecretsNotFoundError",
    "SecretsProvider",
    "VaultSecretsProvider",
    "make_secrets_provider",
]


def make_secrets_provider(name: str) -> SecretsProvider:
    """Factory: pick a provider by name.

    Currently 'env' is fully functional; 'vault' is a stub that raises until
    a vault client is wired in (faz 8+).
    """
    if name == "env":
        return EnvSecretsProvider()
    if name == "vault":
        return VaultSecretsProvider()
    raise ValueError(f"unknown secrets provider: {name!r}")
