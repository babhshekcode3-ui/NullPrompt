"""Typed references to immutable source evidence."""

from pydantic import BaseModel, ConfigDict, Field


class EvidenceReference(BaseModel):
    """Stable metadata for one retained physical log line."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    record_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_length: int = Field(ge=0)
    source_name: str = Field(min_length=1)
    byte_offset: int = Field(ge=0)
