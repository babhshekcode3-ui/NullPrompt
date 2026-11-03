from pathlib import Path

import pytest

from nullprompt.provenance import EvidenceIntegrityError, EvidenceStore


def test_store_rejects_overwrite_of_corrupted_existing_record(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")
    reference, created = store.add_record(b"original\n", source_name="auth.log", byte_offset=0)
    assert created

    (store.root / f"{reference.record_id}.bin").write_bytes(b"tampered\n")

    with pytest.raises(EvidenceIntegrityError, match="digest mismatch"):
        store.add_record(b"original\n", source_name="auth.log", byte_offset=0)


def test_verify_detects_missing_and_modified_evidence(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")
    reference, _ = store.add_record(b"record\n", source_name="auth.log", byte_offset=12)
    path = store.root / f"{reference.record_id}.bin"

    path.unlink()
    with pytest.raises(EvidenceIntegrityError, match="unavailable"):
        store.verify(reference)

    path.write_bytes(b"different\n")
    with pytest.raises(EvidenceIntegrityError, match="digest mismatch"):
        store.verify(reference)


def test_store_rejects_unsafe_reference_fields(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")

    with pytest.raises(ValueError, match="file name"):
        store.add_record(b"x", source_name="../outside.log", byte_offset=0)
    with pytest.raises(ValueError, match="non-negative"):
        store.add_record(b"x", source_name="auth.log", byte_offset=-1)
