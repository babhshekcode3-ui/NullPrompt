"""Typed normalized records and explicit parse failures."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from nullprompt.provenance.models import EvidenceReference


LogFormat = Literal["auth_log", "apache_access", "apache_error", "windows_event_xml"]


class NormalizedEvent(BaseModel):
    """Parsed fields linked to the exact retained source record."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence: EvidenceReference
    source_format: LogFormat
    timestamp_text: str
    host: str | None = None
    process: str | None = None
    process_id: int | None = Field(default=None, ge=0)
    message: str
    fields: dict[str, str | int | None] = Field(default_factory=dict)


class ParseFailure(BaseModel):
    """A record that could not be parsed; its original evidence remains linked."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence: EvidenceReference
    source_format: LogFormat
    reason: Literal["invalid_encoding", "malformed_record"]
    detail: str
