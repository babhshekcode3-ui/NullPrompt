from pathlib import Path

import pytest

from nullprompt.ingestion import WindowsEventXmlIngestor, WindowsXmlIngestionError
from nullprompt.provenance import EvidenceStore


XML_EVENT = (
    b"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    b"<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
    b"<EventID>4625</EventID><Level>0</Level>"
    b"<TimeCreated SystemTime='2026-11-02T12:00:00.000Z'/>"
    b"<EventRecordID>1234</EventRecordID><Channel>Security</Channel>"
    b"<Computer>WIN01.example.test</Computer></System>"
    b"<EventData><Data Name='TargetUserName'>guest</Data>"
    b"<Data Name='IpAddress'>192.0.2.20</Data></EventData></Event>"
)


def test_ingestion_retains_each_event_byte_slice_and_offset(tmp_path: Path) -> None:
    source = tmp_path / "security.xml"
    first = XML_EVENT
    second = XML_EVENT.replace(b"1234", b"1235")
    document = b"<?xml version='1.0' encoding='UTF-8'?>\n<Events>\n  " + first + b"\n  " + second + b"\n</Events>\n"
    source.write_bytes(document)
    store = EvidenceStore(tmp_path / "evidence")

    result = WindowsEventXmlIngestor(store).ingest_file(source)

    assert len(result.records) == 2
    assert result.newly_stored == 2
    assert result.records[0].byte_offset == document.index(first)
    assert result.records[1].byte_offset == document.index(second)
    assert store.read_verified(result.records[0]) == first
    assert store.read_verified(result.records[1]) == second


def test_reingestion_is_idempotent(tmp_path: Path) -> None:
    source = tmp_path / "security.xml"
    source.write_bytes(b"<Events>" + XML_EVENT + b"</Events>")
    ingestor = WindowsEventXmlIngestor(EvidenceStore(tmp_path / "evidence"))

    first = ingestor.ingest_file(source)
    second = ingestor.ingest_file(source)

    assert [record.record_id for record in first.records] == [record.record_id for record in second.records]
    assert second.newly_stored == 0
    assert second.duplicate_count == 1


def test_dtd_and_malformed_xml_are_rejected_without_partial_ingestion(tmp_path: Path) -> None:
    source = tmp_path / "security.xml"
    evidence_root = tmp_path / "evidence"
    source.write_bytes(b"<!DOCTYPE Events [<!ENTITY x 'bad'>]><Events>" + XML_EVENT + b"</Events>")
    with pytest.raises(WindowsXmlIngestionError, match="DTD"):
        WindowsEventXmlIngestor(EvidenceStore(evidence_root)).ingest_file(source)
    assert list(evidence_root.iterdir()) == []

    source.write_bytes(b"<Events>" + XML_EVENT + b"<Event>")
    with pytest.raises(WindowsXmlIngestionError, match="Malformed"):
        WindowsEventXmlIngestor(EvidenceStore(evidence_root)).ingest_file(source)
    assert list(evidence_root.iterdir()) == []


def test_non_utf8_xml_export_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "security.xml"
    source.write_bytes(b"\xff\xfe<\x00E\x00v\x00e\x00n\x00t\x00s\x00/\x00>\x00")

    with pytest.raises(WindowsXmlIngestionError, match="UTF-8"):
        WindowsEventXmlIngestor(EvidenceStore(tmp_path / "evidence")).ingest_file(source)
