"""Read prepared log files as exact physical-line evidence records."""

from dataclasses import dataclass
from pathlib import Path

from nullprompt.provenance.models import EvidenceReference
from nullprompt.provenance.store import EvidenceStore


@dataclass(frozen=True)
class IngestionResult:
    """Outcome and source references produced by one file ingestion."""

    source_name: str
    records: tuple[EvidenceReference, ...]
    newly_stored: int

    @property
    def duplicate_count(self) -> int:
        return len(self.records) - self.newly_stored


class FileIngestor:
    """Ingest files without decoding or changing their bytes."""

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def ingest_file(self, source: str | Path) -> IngestionResult:
        """Store one physical line per record, preserving all bytes and line endings.

        Traditional auth.log and Apache records use this boundary in the approved
        MVP. Multiline or continuation records are not joined or decoded here.
        """
        source_path = Path(source)
        if source_path.is_symlink():
            raise ValueError("Source log must not be a symlink")
        if not source_path.is_file():
            raise ValueError("Source log must be a regular file")
        source_name = source_path.name
        references: list[EvidenceReference] = []
        newly_stored = 0
        offset = 0
        with source_path.open("rb") as source_file:
            for raw_line in source_file:
                reference, created = self.store.add_record(
                    raw_line,
                    source_name=source_name,
                    byte_offset=offset,
                )
                references.append(reference)
                newly_stored += int(created)
                offset += len(raw_line)
        return IngestionResult(
            source_name=source_name,
            records=tuple(references),
            newly_stored=newly_stored,
        )
