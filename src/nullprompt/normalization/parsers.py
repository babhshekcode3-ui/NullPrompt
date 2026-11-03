"""Strict, bounded parsers for the approved MVP log families."""

import re
import xml.etree.ElementTree as ET

from nullprompt.normalization.models import LogFormat, NormalizedEvent, ParseFailure
from nullprompt.provenance.models import EvidenceReference
from nullprompt.provenance.store import EvidenceStore

_AUTH_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<process>[A-Za-z0-9_./-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
)
_APACHE_ACCESS_RE = re.compile(
    r'^(?P<host>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>(?:\\.|[^"\\])*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>(?:\\.|[^"\\])*)"'
    r'\s+"(?P<user_agent>(?:\\.|[^"\\])*)")?$'
)
_APACHE_ERROR_RE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+"
    r"(?P<metadata>(?:\[[^\]]+\]\s*)+)"
    r"(?P<message>.*)$"
)
_BRACKET_RE = re.compile(r"\[([^\]]+)\]")


def parse_record(
    reference: EvidenceReference, store: EvidenceStore, source_format: LogFormat
) -> NormalizedEvent | ParseFailure:
    """Parse one verified evidence record without changing or discarding it."""
    if source_format not in ("auth_log", "apache_access", "apache_error", "windows_event_xml"):
        raise ValueError("Unsupported log format")
    raw_bytes = store.read_verified(reference)
    if source_format == "windows_event_xml":
        return _parse_windows_event_xml(reference, raw_bytes)
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ParseFailure(
            evidence=reference,
            source_format=source_format,
            reason="invalid_encoding",
            detail="Record is not valid UTF-8",
        )
    line = text.rstrip("\r\n")

    if source_format == "auth_log":
        return _parse_auth(reference, line)
    if source_format == "apache_access":
        return _parse_apache_access(reference, line)
    return _parse_apache_error(reference, line)


def _parse_auth(reference: EvidenceReference, line: str) -> NormalizedEvent | ParseFailure:
    match = _AUTH_RE.fullmatch(line)
    if match is None:
        return _failure(reference, "auth_log", "Record does not match the supported syslog auth.log shape")
    values = match.groupdict()
    return NormalizedEvent(
        evidence=reference,
        source_format="auth_log",
        timestamp_text=values["timestamp"],
        host=values["host"],
        process=values["process"],
        process_id=int(values["pid"]) if values["pid"] else None,
        message=values["message"],
    )


def _parse_apache_access(
    reference: EvidenceReference, line: str
) -> NormalizedEvent | ParseFailure:
    match = _APACHE_ACCESS_RE.fullmatch(line)
    if match is None:
        return _failure(reference, "apache_access", "Record does not match supported Apache common or combined format")
    values = match.groupdict()
    request = values["request"]
    request_parts = request.split(" ", 2)
    if len(request_parts) != 3 or any(not part for part in request_parts):
        return _failure(reference, "apache_access", "Request field must contain method, target, and protocol")
    try:
        size: int | None = None if values["size"] == "-" else int(values["size"])
        if size is not None and size < 0:
            raise ValueError
    except ValueError:
        return _failure(reference, "apache_access", "Response size is not a non-negative integer or '-' ")
    fields: dict[str, str | int | None] = {
        "ident": _dash_to_none(values["ident"]),
        "authenticated_user": _dash_to_none(values["user"]),
        "method": request_parts[0],
        "request_target": request_parts[1],
        "protocol": request_parts[2],
        "status": int(values["status"]),
        "response_bytes": size,
        "referer": _dash_to_none(values["referer"]),
        "user_agent": _dash_to_none(values["user_agent"]),
    }
    return NormalizedEvent(
        evidence=reference,
        source_format="apache_access",
        timestamp_text=values["timestamp"],
        host=values["host"],
        message=request,
        fields=fields,
    )


def _parse_apache_error(
    reference: EvidenceReference, line: str
) -> NormalizedEvent | ParseFailure:
    match = _APACHE_ERROR_RE.fullmatch(line)
    if match is None:
        return _failure(reference, "apache_error", "Record does not match supported Apache error-log shape")
    values = match.groupdict()
    metadata = _BRACKET_RE.findall(values["metadata"])
    if not metadata:
        return _failure(reference, "apache_error", "Apache error record has no metadata fields")
    fields: dict[str, str | int | None] = {"metadata": " | ".join(metadata)}
    process_id = None
    for item in metadata:
        if item.startswith("client "):
            fields["client"] = item.removeprefix("client ")
        elif item.startswith("pid "):
            pid_match = re.match(r"pid\s+(\d+)", item)
            if pid_match:
                process_id = int(pid_match.group(1))
        elif ":" in item and "severity" not in fields:
            module, severity = item.rsplit(":", 1)
            fields["module"] = module
            fields["severity"] = severity
    return NormalizedEvent(
        evidence=reference,
        source_format="apache_error",
        timestamp_text=values["timestamp"],
        process="apache",
        process_id=process_id,
        message=values["message"],
        fields=fields,
    )


def _parse_windows_event_xml(
    reference: EvidenceReference, raw_bytes: bytes
) -> NormalizedEvent | ParseFailure:
    try:
        raw_bytes.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        return ParseFailure(
            evidence=reference,
            source_format="windows_event_xml",
            reason="invalid_encoding",
            detail="Event element is not valid UTF-8",
        )
    try:
        event = ET.fromstring(raw_bytes)
    except ET.ParseError:
        return _failure(reference, "windows_event_xml", "Event element is malformed XML")
    if _local_name(event.tag) != "Event":
        return _failure(reference, "windows_event_xml", "XML record root is not an Event element")
    system = _find_child(event, "System")
    if system is None:
        return _failure(reference, "windows_event_xml", "Event element has no System section")
    event_id_node = _find_child(system, "EventID")
    timestamp_node = _find_child(system, "TimeCreated")
    computer_node = _find_child(system, "Computer")
    if event_id_node is None or not (event_id_node.text or "").strip():
        return _failure(reference, "windows_event_xml", "Event System section has no EventID")
    if timestamp_node is None or not timestamp_node.attrib.get("SystemTime"):
        return _failure(reference, "windows_event_xml", "Event System section has no SystemTime")
    try:
        event_id = int((event_id_node.text or "").strip())
    except ValueError:
        return _failure(reference, "windows_event_xml", "EventID is not an integer")

    provider_node = _find_child(system, "Provider")
    fields: dict[str, str | int | None] = {"event_id": event_id}
    if provider_node is not None and provider_node.attrib.get("Name"):
        fields["provider"] = provider_node.attrib["Name"]
    for field_name, tag_name in (
        ("level", "Level"),
        ("task", "Task"),
        ("opcode", "Opcode"),
        ("record_id", "EventRecordID"),
        ("channel", "Channel"),
    ):
        node = _find_child(system, tag_name)
        if node is None or node.text is None:
            continue
        value = node.text.strip()
        fields[field_name] = int(value) if field_name in ("level", "task", "opcode", "record_id") and value.isdigit() else value

    event_data = _find_child(event, "EventData")
    data_values: list[str] = []
    if event_data is not None:
        for index, node in enumerate(list(event_data)):
            if _local_name(node.tag) != "Data":
                continue
            name = node.attrib.get("Name") or f"item_{index}"
            key = f"data.{name}"
            suffix = 2
            while key in fields:
                key = f"data.{name}_{suffix}"
                suffix += 1
            value = "".join(node.itertext())
            fields[key] = value
            data_values.append(value)

    rendering_info = _find_child(event, "RenderingInfo")
    rendered_message = _find_child(rendering_info, "Message") if rendering_info is not None else None
    message = "".join(rendered_message.itertext()).strip() if rendered_message is not None else "; ".join(data_values)
    return NormalizedEvent(
        evidence=reference,
        source_format="windows_event_xml",
        timestamp_text=timestamp_node.attrib["SystemTime"],
        host=(computer_node.text or "").strip() or None if computer_node is not None else None,
        message=message,
        fields=fields,
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].split(":")[-1]


def _find_child(parent: ET.Element, name: str) -> ET.Element | None:
    return next((child for child in list(parent) if _local_name(child.tag) == name), None)


def _dash_to_none(value: str | None) -> str | None:
    return None if value in (None, "-") else value


def _failure(
    reference: EvidenceReference, source_format: LogFormat, detail: str
) -> ParseFailure:
    return ParseFailure(
        evidence=reference,
        source_format=source_format,
        reason="malformed_record",
        detail=detail,
    )
