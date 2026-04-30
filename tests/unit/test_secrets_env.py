import pytest

from netauto.secrets.base import (
    CredentialKind,
    DeviceCredentials,
    SecretsNotFoundError,
)
from netauto.secrets.env import EnvSecretsProvider


def test_env_provider_device_specific_lookup() -> None:
    env = {
        "NETAUTO_R1_MOCK_RO_USERNAME": "ro_user_r1",
        "NETAUTO_R1_MOCK_RO_PASSWORD": "secret_r1",
        "NETAUTO_DEFAULT_RO_USERNAME": "shared_default",
    }
    p = EnvSecretsProvider(env=env)
    creds = p.get_device_credentials("r1-mock", CredentialKind.READ_ONLY)
    assert creds.username == "ro_user_r1"
    assert creds.password is not None
    assert creds.password.get_secret_value() == "secret_r1"
    assert creds.kind is CredentialKind.READ_ONLY


def test_env_provider_falls_back_to_default() -> None:
    env = {
        "NETAUTO_DEFAULT_RO_USERNAME": "shared",
        "NETAUTO_DEFAULT_RO_PASSWORD": "shared_pw",
    }
    p = EnvSecretsProvider(env=env)
    creds = p.get_device_credentials("r1-mock", CredentialKind.READ_ONLY)
    assert creds.username == "shared"
    assert creds.password is not None
    assert creds.password.get_secret_value() == "shared_pw"


def test_env_provider_per_device_isolation() -> None:
    env = {
        "NETAUTO_R1_MOCK_RO_USERNAME": "ro_r1",
        "NETAUTO_R2_MOCK_RO_USERNAME": "ro_r2",
    }
    p = EnvSecretsProvider(env=env)
    r1 = p.get_device_credentials("r1-mock", CredentialKind.READ_ONLY)
    r2 = p.get_device_credentials("r2-mock", CredentialKind.READ_ONLY)
    assert r1.username == "ro_r1"
    assert r2.username == "ro_r2"


def test_env_provider_ro_rw_split() -> None:
    env = {
        "NETAUTO_R1_RO_USERNAME": "collector",
        "NETAUTO_R1_RW_USERNAME": "responder",
        "NETAUTO_R1_RW_PASSWORD": "rw_pw",
    }
    p = EnvSecretsProvider(env=env)
    ro = p.get_device_credentials("r1", CredentialKind.READ_ONLY)
    rw = p.get_device_credentials("r1", CredentialKind.READ_WRITE)
    assert ro.username == "collector"
    assert ro.password is None
    assert rw.username == "responder"
    assert rw.password is not None
    assert rw.password.get_secret_value() == "rw_pw"


def test_env_provider_missing_credentials_raises() -> None:
    p = EnvSecretsProvider(env={})
    with pytest.raises(SecretsNotFoundError, match="no ro credentials"):
        p.get_device_credentials("nope", CredentialKind.READ_ONLY)


def test_env_provider_hostname_normalizes_dashes_and_dots() -> None:
    env = {"NETAUTO_R1_EDGE_DC1_EXAMPLE_COM_RO_USERNAME": "x"}
    p = EnvSecretsProvider(env=env)
    creds = p.get_device_credentials("r1-edge.dc1.example.com", CredentialKind.READ_ONLY)
    assert creds.username == "x"


def test_env_provider_password_optional() -> None:
    """SSH-key-only auth: username present, no password env var."""
    env = {"NETAUTO_R1_RO_USERNAME": "key_user"}
    p = EnvSecretsProvider(env=env)
    creds = p.get_device_credentials("r1", CredentialKind.READ_ONLY)
    assert creds.password is None


def test_device_credentials_extra_field_forbidden() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        DeviceCredentials(
            username="x",
            kind=CredentialKind.READ_ONLY,
            unknown="x",  # type: ignore[call-arg]
        )
