from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from datetime import datetime, timezone
from collections import Counter


@dataclass
class Fact:
    """
    Canonical Fact representing a relationship between two resources.
    """

    fact_type: str
    subject_id: str
    subject_type: str
    object_id: str
    object_type: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Internal tracking
    created_at: Optional[str] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        if self.metadata is None:
            self.metadata = {}

    def to_dict(self, include_created_at: bool = True) -> Dict[str, Any]:
        payload = {
            "fact_type": self.fact_type,
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
            "object_id": self.object_id,
            "object_type": self.object_type,
            "metadata": self.metadata,
        }
        if include_created_at:
            payload["created_at"] = self.created_at
        return payload

    def to_stable_dict(self) -> Dict[str, Any]:
        """
        Deterministic serialization for testing/diff.
        created_at is intentionally excluded.
        """
        return {
            "fact_type": self.fact_type,
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
            "object_id": self.object_id,
            "object_type": self.object_type,
            "metadata": _stable_value(self.metadata),
        }

    def __repr__(self) -> str:
        return f"Fact(type={self.fact_type}, {self.subject_id} → {self.object_id})"


@dataclass
class FactCollection:
    """
    Collection of Facts with validation metadata.
    """
    scan_id: str
    facts: list[Fact] = field(default_factory=list)
    skipped_count: int = 0
    error_count: int = 0
    warning_count: int = 0
    errors: list[Dict[str, Any]] = field(default_factory=list)

    def add(self, fact: Fact):
        self.facts.append(fact)

    def extend(self, facts: list[Fact]):
        self.facts.extend(facts)

    def __len__(self) -> int:
        return len(self.facts)

    def __iter__(self):
        return iter(self.facts)

    def summary_payload(self, raw_fact_count: Optional[int] = None) -> Dict[str, Any]:
        raw_count = raw_fact_count if raw_fact_count is not None else (len(self.facts) + self.skipped_count)
        fact_counts = Counter(f.fact_type for f in self.facts)
        return {
            "scan_id": self.scan_id,
            "raw_fact_count": raw_count,
            "valid_fact_count": len(self.facts),
            "skipped_count": self.skipped_count,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "fact_counts_by_type": dict(sorted(fact_counts.items())),
        }


@dataclass
class FactPipelineDebugResult:
    """
    Debug-friendly result for the whole Fact pipeline.
    """
    scan_id: str
    k8s_raw_facts: list[Fact] = field(default_factory=list)
    lateral_raw_facts: list[Fact] = field(default_factory=list)
    aws_raw_facts: list[Fact] = field(default_factory=list)
    all_raw_facts: list[Fact] = field(default_factory=list)
    valid_facts: list[Fact] = field(default_factory=list)
    validation_errors: list[Dict[str, Any]] = field(default_factory=list)
    bridge_output: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_collection(self) -> FactCollection:
        collection = FactCollection(scan_id=self.scan_id)
        collection.facts = list(self.valid_facts)
        collection.errors = list(self.validation_errors)
        collection.error_count = int(self.summary.get("error_count", 0))
        collection.warning_count = int(self.summary.get("warning_count", 0))
        collection.skipped_count = int(self.summary.get("skipped_count", 0))
        return collection


def _stable_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _stable_value(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_stable_value(v) for v in value]
    return value