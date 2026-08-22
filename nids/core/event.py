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
