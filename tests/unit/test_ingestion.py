from pathlib import Path

import pytest

from nullprompt.ingestion import FileIngestor
from nullprompt.provenance import EvidenceStore


def test_ingestion_preserves_bytes_line_endings_and_offsets(tmp_path: Path) -> None:
    source = tmp_path / "auth.log"
    evidence_root = tmp_path / "evidence"
    original = b"first\r\nsecond\nlast-without-newline"
    source.write_bytes(original)

    result = FileIngestor(EvidenceStore(evidence_root)).ingest_file(source)

    assert result.source_name == "auth.log"
    assert [record.byte_offset for record in result.records] == [0, 7, 14]
    assert [record.byte_length for record in result.records] == [7, 7, 20]
    assert [EvidenceStore(evidence_root).read_verified(record) for record in result.records] == [
        b"first\r\n",
        b"second\n",
        b"last-without-newline",
    ]
    assert b"".join(
        EvidenceStore(evidence_root).read_verified(record) for record in result.records
    ) == original
    assert result.newly_stored == 3
    assert result.duplicate_count == 0


def test_reingestion_is_idempotent_and_returns_same_record_ids(tmp_path: Path) -> None:
    source = tmp_path / "access.log"
    source.write_bytes(b"entry\nentry\n")
    ingestor = FileIngestor(EvidenceStore(tmp_path / "evidence"))

    first = ingestor.ingest_file(source)
    second = ingestor.ingest_file(source)

    assert [record.record_id for record in first.records] == [
        record.record_id for record in second.records
    ]
    assert first.newly_stored == 2
    assert first.duplicate_count == 0
    assert second.newly_stored == 0
    assert second.duplicate_count == 2


def test_binary_malformed_input_is_retained_without_decoding(tmp_path: Path) -> None:
    source = tmp_path / "malformed.log"
    source.write_bytes(b"valid\n\xff\x00\xfe\n")
    store = EvidenceStore(tmp_path / "evidence")

    result = FileIngestor(store).ingest_file(source)

    assert [store.read_verified(record) for record in result.records] == [
        b"valid\n",
        b"\xff\x00\xfe\n",
    ]


def test_empty_file_produces_no_records(tmp_path: Path) -> None:
    source = tmp_path / "empty.log"
    source.write_bytes(b"")

    result = FileIngestor(EvidenceStore(tmp_path / "evidence")).ingest_file(source)

    assert result.records == ()
    assert result.newly_stored == 0
    assert result.duplicate_count == 0


def test_non_file_input_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular file"):
        FileIngestor(EvidenceStore(tmp_path / "evidence")).ingest_file(tmp_path)
