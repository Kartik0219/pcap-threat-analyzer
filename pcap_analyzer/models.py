"""Shared data structures for detection findings."""

from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single suspicious-activity finding produced by a detector."""

    detector: str
    category: str
    confidence: str  # "low" | "medium" | "high"
    src_ip: str
    dst_ip: str
    summary: str
    first_seen: float
    last_seen: float
    evidence: dict = field(default_factory=dict)

    def as_row(self) -> dict:
        """Flat representation used by report writers."""
        return {
            "detector": self.detector,
            "category": self.category,
            "confidence": self.confidence,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "summary": self.summary,
            "evidence": self.evidence,
        }
