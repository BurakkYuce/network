import pytest

from netauto.secrets import (
    EnvSecretsProvider,
    SecretsProvider,
    VaultSecretsProvider,
    make_secrets_provider,
)


def test_make_env_provider() -> None:
    p = make_secrets_provider("env")
    assert isinstance(p, EnvSecretsProvider)
    assert isinstance(p, SecretsProvider)


def test_make_vault_provider() -> None:
    p = make_secrets_provider("vault")
    assert isinstance(p, VaultSecretsProvider)
    assert isinstance(p, SecretsProvider)


def test_make_unknown_provider_raises() -> None:
    with pytest.raises(ValueError, match="unknown secrets provider"):
        make_secrets_provider("nope")
