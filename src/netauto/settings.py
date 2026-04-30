from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NETAUTO_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    db_url: str = "sqlite:///./netauto.db"
    log_level: str = "INFO"
    testbed_path: Path = Path("config/inventory/testbed.yaml")
    audit_log_path: Path = Path("./audit.jsonl")
    snapshots_dir: Path = Path("./snapshots")
    fixtures_dir: Path = Path("tests/fixtures/genie_learn")
    ephemeral_paths_file: Path = Path("config/ephemeral_paths.yaml")
    rules_dir: Path = Path("config/detections")


settings = Settings()
