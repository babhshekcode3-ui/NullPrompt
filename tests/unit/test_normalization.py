from pathlib import Path

from nullprompt.normalization.models import NormalizedEvent, ParseFailure
from nullprompt.normalization.parsers import parse_record
from nullprompt.provenance import EvidenceStore


def _stored_record(tmp_path: Path, payload: bytes):
    store = EvidenceStore(tmp_path / "evidence")
    reference, _ = store.add_record(payload, source_name="sample.log", byte_offset=0)
    return store, reference


def test_parse_auth_log_retains_provenance_and_untrusted_message(tmp_path: Path) -> None:
    payload = b"Nov  2 12:34:56 host sshd[42]: Failed login from 192.0.2.1\n"
    store, reference = _stored_record(tmp_path, payload)

    event = parse_record(reference, store, "auth_log")

    assert isinstance(event, NormalizedEvent)
    assert event.evidence == reference
    assert event.timestamp_text == "Nov  2 12:34:56"
    assert event.host == "host"
    assert event.process == "sshd"
    assert event.process_id == 42
    assert event.message == "Failed login from 192.0.2.1"


def test_parse_apache_combined_access_line(tmp_path: Path) -> None:
    payload = (
        b'192.0.2.10 - alice [02/Nov/2026:12:00:00 +0000] '
        b'"GET /search?q=example HTTP/1.1" 200 123 "-" "ExampleBot/1.0"\n'
    )
    store, reference = _stored_record(tmp_path, payload)

    event = parse_record(reference, store, "apache_access")

    assert isinstance(event, NormalizedEvent)
    assert event.evidence == reference
    assert event.host == "192.0.2.10"
    assert event.fields["method"] == "GET"
    assert event.fields["request_target"] == "/search?q=example"
    assert event.fields["status"] == 200
    assert event.fields["response_bytes"] == 123
    assert event.fields["referer"] is None


def test_parse_apache_error_record(tmp_path: Path) -> None:
    payload = (
        b"[Mon Nov 02 12:00:00.123456 2026] [core:error] "
        b"[pid 321:tid 44] [client 192.0.2.10:5555] request failed\n"
    )
    store, reference = _stored_record(tmp_path, payload)

    event = parse_record(reference, store, "apache_error")

    assert isinstance(event, NormalizedEvent)
    assert event.evidence == reference
    assert event.process_id == 321
    assert event.fields["module"] == "core"
    assert event.fields["severity"] == "error"
    assert event.fields["client"] == "192.0.2.10:5555"
    assert event.message == "request failed"


def test_malformed_and_undecodable_records_are_explicit_failures(tmp_path: Path) -> None:
    store, malformed_ref = _stored_record(tmp_path, b"not an auth record\n")
    malformed = parse_record(malformed_ref, store, "auth_log")
    assert isinstance(malformed, ParseFailure)
    assert malformed.reason == "malformed_record"
    assert malformed.evidence == malformed_ref

    store, invalid_ref = _stored_record(tmp_path, b"\xff\xfe\n")
    invalid = parse_record(invalid_ref, store, "apache_access")
    assert isinstance(invalid, ParseFailure)
    assert invalid.reason == "invalid_encoding"
    assert invalid.evidence == invalid_ref


def test_invalid_format_name_is_rejected(tmp_path: Path) -> None:
    store, reference = _stored_record(tmp_path, b"record\n")

    try:
        parse_record(reference, store, "unknown")
    except ValueError as exc:
        assert str(exc) == "Unsupported log format"
    else:
        raise AssertionError("Unsupported log format should be rejected")


def test_apache_access_rejects_empty_request_components(tmp_path: Path) -> None:
    payload = b'192.0.2.1 - - [02/Nov/2026:12:00:00 +0000] "GET  / HTTP/1.1" 200 1\n'
    store, reference = _stored_record(tmp_path, payload)

    result = parse_record(reference, store, "apache_access")

    assert isinstance(result, ParseFailure)
    assert result.reason == "malformed_record"


def test_parse_windows_security_event_xml_preserves_reference_and_fields(tmp_path: Path) -> None:
    from nullprompt.ingestion import WindowsEventXmlIngestor

    event_xml = (
        b"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        b"<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        b"<EventID>4625</EventID><TimeCreated SystemTime='2026-11-02T12:00:00Z'/>"
        b"<EventRecordID>1234</EventRecordID><Channel>Security</Channel>"
        b"<Computer>WIN01</Computer></System>"
        b"<EventData><Data Name='TargetUserName'>guest</Data>"
        b"<Data Name='IpAddress'>192.0.2.20</Data></EventData></Event>"
    )
    source = tmp_path / "security.xml"
    source.write_bytes(b"<Events>" + event_xml + b"</Events>")
    store = EvidenceStore(tmp_path / "evidence")
    ingestion = WindowsEventXmlIngestor(store).ingest_file(source)

    event = parse_record(ingestion.records[0], store, "windows_event_xml")

    assert isinstance(event, NormalizedEvent)
    assert event.evidence == ingestion.records[0]
    assert event.source_format == "windows_event_xml"
    assert event.timestamp_text == "2026-11-02T12:00:00Z"
    assert event.host == "WIN01"
    assert event.fields["event_id"] == 4625
    assert event.fields["channel"] == "Security"
    assert event.fields["data.TargetUserName"] == "guest"


def test_malformed_windows_event_element_is_explicit_parse_failure(tmp_path: Path) -> None:
    store, reference = _stored_record(tmp_path, b"<Event><System></Event>")

    result = parse_record(reference, store, "windows_event_xml")

    assert isinstance(result, ParseFailure)
    assert result.source_format == "windows_event_xml"
    assert result.reason == "malformed_record"
    assert result.evidence == reference
