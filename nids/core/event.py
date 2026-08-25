from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    LOW = "scazuta"
    MEDIUM = "medie"
    HIGH = "ridicata"


@dataclass
class Event:
    event_type: str
    source_ip: str
    severity: Severity
    description: str
    dest_ip: str | None = None
    src_port: int | None = None
    dest_port: int | None = None
    protocol: str | None = None
    assessment_json: str | None = None
