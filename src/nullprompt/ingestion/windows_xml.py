"""Byte-preserving ingestion for prepared Windows Event Log XML exports."""

from pathlib import Path
from xml.parsers import expat

from nullprompt.ingestion.file_ingestor import IngestionResult
from nullprompt.provenance.models import EvidenceReference
from nullprompt.provenance.store import EvidenceStore


class WindowsXmlIngestionError(ValueError):
    """Raised when an XML export is malformed or uses an unsupported feature."""


class WindowsEventXmlIngestor:
    """Retain each XML Event element as an exact, independently hashed record.

    Supports UTF-8 XML exports. DTDs and entity declarations are rejected.
    Inter-element formatting is not part of an Event record; each retained byte
    slice begins at the Event start tag and ends at its closing tag.
    """

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def ingest_file(self, source: str | Path) -> IngestionResult:
        source_path = Path(source)
        if source_path.is_symlink():
            raise ValueError("Source XML must not be a symlink")
        if not source_path.is_file():
            raise ValueError("Source XML must be a regular file")
        raw_xml = source_path.read_bytes()
        if raw_xml.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00")):
            raise WindowsXmlIngestionError("Only UTF-8 Windows Event XML exports are supported")

        spans: list[tuple[int, bytes]] = []
        active_start: int | None = None
        parser = expat.ParserCreate(namespace_separator="}")
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

        def local_name(name: str) -> str:
            return name.rsplit("}", 1)[-1].split(":")[-1]

        def on_start(name: str, _attributes: dict[str, str]) -> None:
            nonlocal active_start
            if local_name(name) == "Event":
                if active_start is not None:
                    raise WindowsXmlIngestionError("Nested Event elements are unsupported")
                active_start = parser.CurrentByteIndex

        def on_end(name: str) -> None:
            nonlocal active_start
            if local_name(name) != "Event":
                return
            if active_start is None:
                raise WindowsXmlIngestionError("Unmatched Event element")
            end_start = parser.CurrentByteIndex
            if raw_xml[end_start:end_start + 2] == b"</":
                end = raw_xml.find(b">", end_start)
            else:
                # Expat reports self-closing element callbacks at its start tag.
                end = raw_xml.find(b">", active_start)
            if end < 0:
                raise WindowsXmlIngestionError("Unterminated Event element")
            spans.append((active_start, raw_xml[active_start:end + 1]))
            active_start = None

        def reject_doctype(*_args: object) -> None:
            raise WindowsXmlIngestionError("DTD declarations are not supported")

        parser.StartElementHandler = on_start
        parser.EndElementHandler = on_end
        parser.StartDoctypeDeclHandler = reject_doctype
        parser.EntityDeclHandler = reject_doctype
        parser.ExternalEntityRefHandler = lambda *_args: 0
        try:
            parser.Parse(raw_xml, True)
        except WindowsXmlIngestionError:
            raise
        except expat.ExpatError as exc:
            raise WindowsXmlIngestionError("Malformed Windows Event XML export") from exc
        if active_start is not None:
            raise WindowsXmlIngestionError("Unterminated Event element")
        if not spans:
            raise WindowsXmlIngestionError("XML export contains no Event elements")

        references: list[EvidenceReference] = []
        newly_stored = 0
        source_name = source_path.name
        for offset, event_bytes in spans:
            reference, created = self.store.add_record(
                event_bytes,
                source_name=source_name,
                byte_offset=offset,
            )
            references.append(reference)
            newly_stored += int(created)
        return IngestionResult(source_name, tuple(references), newly_stored)
