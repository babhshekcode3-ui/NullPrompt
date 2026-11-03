"""Content-addressed storage and integrity checks for original evidence."""

import hashlib
import os
from pathlib import Path

from nullprompt.provenance.models import EvidenceReference


class EvidenceIntegrityError(RuntimeError):
    """Raised when retained evidence does not match its reference."""


class EvidenceStore:
    """Store exact evidence bytes without silently replacing existing records."""

    def __init__(self, root: str | Path = "data/raw") -> None:
        self.root = Path(root)
        if self.root.exists() and self.root.is_symlink():
            raise ValueError("Evidence directory must not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.root.is_dir():
            raise ValueError("Evidence path must be a directory")

    def add_record(
        self, raw_bytes: bytes, *, source_name: str, byte_offset: int, source_document_id: str | None = None
    ) -> tuple[EvidenceReference, bool]:
        """Retain bytes exactly; return (reference, newly_created)."""
        if not isinstance(raw_bytes, bytes):
            raise TypeError("raw_bytes must be bytes")
        if not source_name or Path(source_name).name != source_name:
            raise ValueError("source_name must be a non-empty file name")
        if byte_offset < 0:
            raise ValueError("byte_offset must be non-negative")

        record_hash = hashlib.sha256(raw_bytes).hexdigest()
        identity = b"\0".join(
            (source_name.encode("utf-8"), str(byte_offset).encode("ascii"), raw_bytes)
        )
        record_id = hashlib.sha256(identity).hexdigest()
        reference = EvidenceReference(
            record_id=record_id,
            sha256=record_hash,
            byte_length=len(raw_bytes),
            source_name=source_name,
            byte_offset=byte_offset,
        )
        destination = self.root / f"{record_id}.bin"
        try:
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            self.verify(reference)
            return reference, False

        try:
            with os.fdopen(descriptor, "wb") as evidence_file:
                evidence_file.write(raw_bytes)
                evidence_file.flush()
                os.fsync(evidence_file.fileno())
        except BaseException:
            # Preserve any partial file for investigation; never replace it silently.
            raise
        return reference, True

    def read_verified(self, reference: EvidenceReference) -> bytes:
        """Read retained bytes and fail if their length or digest has changed."""
        if not isinstance(reference, EvidenceReference):
            raise TypeError("reference must be an EvidenceReference")
        path = self.root / f"{reference.record_id}.bin"
        if path.is_symlink():
            raise EvidenceIntegrityError("Evidence record must not be a symlink")
        try:
            raw_bytes = path.read_bytes()
        except OSError as exc:
            raise EvidenceIntegrityError("Evidence record is unavailable") from exc
        digest = hashlib.sha256(raw_bytes).hexdigest()
        if len(raw_bytes) != reference.byte_length or digest != reference.sha256:
            raise EvidenceIntegrityError("Evidence length or SHA-256 digest mismatch")
        return raw_bytes

    def verify(self, reference: EvidenceReference) -> bool:
        """Verify a retained record; raise EvidenceIntegrityError on any mismatch."""
        self.read_verified(reference)
        return True
