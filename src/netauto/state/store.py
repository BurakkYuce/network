from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from netauto.state.canonical import DeviceState
from netauto.state.models.v1 import DeviceStateV1


@dataclass(frozen=True)
class SnapshotInfo:
    id: int
    captured_at: datetime
    schema_version: int


class Base(DeclarativeBase):
    pass


class DeviceRow(Base):
    __tablename__ = "device"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    platform: Mapped[str] = mapped_column(String(32))
    role: Mapped[str] = mapped_column(String(64), default="unknown")
    tier: Mapped[int] = mapped_column(Integer, default=3)
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    site: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tags: Mapped[Any] = mapped_column(JSON, default=list)


class StateSnapshotRow(Base):
    __tablename__ = "state_snapshot"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id"), index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    schema_version: Mapped[int] = mapped_column(Integer)
    state_json: Mapped[Any] = mapped_column(JSON)
    raw_config_path: Mapped[str | None] = mapped_column(String(512), nullable=True)


class StateStore:
    def __init__(self, db_url: str, *, create_schema: bool = False) -> None:
        self.engine = create_engine(db_url, future=True)
        if create_schema:
            Base.metadata.create_all(self.engine)

    def upsert_device(
        self,
        *,
        hostname: str,
        platform: str,
        role: str = "unknown",
        tier: int = 3,
        criticality: int = 3,
        tags: list[str] | None = None,
        site: str | None = None,
    ) -> int:
        tags_value = list(tags or [])
        with Session(self.engine) as s:
            existing = s.execute(
                select(DeviceRow).where(DeviceRow.hostname == hostname)
            ).scalar_one_or_none()
            if existing is None:
                row = DeviceRow(
                    hostname=hostname,
                    platform=platform,
                    role=role,
                    tier=tier,
                    criticality=criticality,
                    tags=tags_value,
                    site=site,
                )
                s.add(row)
                s.commit()
                return row.id
            existing.platform = platform
            existing.role = role
            existing.tier = tier
            existing.criticality = criticality
            existing.tags = tags_value
            existing.site = site
            s.commit()
            return existing.id

    def get_device_id(self, hostname: str) -> int | None:
        with Session(self.engine) as s:
            row = s.execute(
                select(DeviceRow.id).where(DeviceRow.hostname == hostname)
            ).scalar_one_or_none()
            return row

    def save_snapshot(
        self,
        *,
        device_id: int,
        state: DeviceState,
        raw_config_path: str | None = None,
    ) -> int:
        with Session(self.engine) as s:
            row = StateSnapshotRow(
                device_id=device_id,
                captured_at=state.captured_at,
                schema_version=state.schema_version,
                state_json=state.model_dump(mode="json"),
                raw_config_path=raw_config_path,
            )
            s.add(row)
            s.commit()
            return row.id

    def latest_snapshot(self, device_id: int) -> DeviceStateV1 | None:
        with Session(self.engine) as s:
            stmt = (
                select(StateSnapshotRow)
                .where(StateSnapshotRow.device_id == device_id)
                .order_by(StateSnapshotRow.captured_at.desc())
                .limit(1)
            )
            row = s.execute(stmt).scalar_one_or_none()
            if row is None:
                return None
            return DeviceStateV1.model_validate(row.state_json)

    def list_snapshots(self, device_id: int) -> list[SnapshotInfo]:
        """Return snapshots for a device, newest first."""
        with Session(self.engine) as s:
            stmt = (
                select(
                    StateSnapshotRow.id,
                    StateSnapshotRow.captured_at,
                    StateSnapshotRow.schema_version,
                )
                .where(StateSnapshotRow.device_id == device_id)
                .order_by(StateSnapshotRow.captured_at.desc())
            )
            return [
                SnapshotInfo(
                    id=row.id, captured_at=row.captured_at, schema_version=row.schema_version
                )
                for row in s.execute(stmt).all()
            ]

    def get_snapshot(self, snapshot_id: int) -> DeviceStateV1 | None:
        with Session(self.engine) as s:
            row = s.execute(
                select(StateSnapshotRow).where(StateSnapshotRow.id == snapshot_id)
            ).scalar_one_or_none()
            if row is None:
                return None
            return DeviceStateV1.model_validate(row.state_json)

    def snapshot_count(self, device_id: int) -> int:
        with Session(self.engine) as s:
            stmt = select(StateSnapshotRow.id).where(StateSnapshotRow.device_id == device_id)
            return len(list(s.execute(stmt)))
