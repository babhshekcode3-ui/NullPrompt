"""Prepared-file evidence ingestion."""

from nullprompt.ingestion.file_ingestor import FileIngestor, IngestionResult
from nullprompt.ingestion.windows_xml import WindowsEventXmlIngestor, WindowsXmlIngestionError

__all__ = [
    "FileIngestor",
    "IngestionResult",
    "WindowsEventXmlIngestor",
    "WindowsXmlIngestionError",
]
