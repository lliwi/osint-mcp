from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class TaskStatus(str, Enum):
    running = "running"
    completed = "completed"
    failed = "failed"
    partial = "partial"


class TargetType(str, Enum):
    domain = "domain"
    ip = "ip"
    email = "email"
    phone = "phone"
    username = "username"
    image = "image"
    file = "file"
    wallet = "wallet"
    url = "url"
    person = "person"
    company = "company"


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    unknown = "unknown"


class Risk(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    unknown = "unknown"


class Finding(BaseModel):
    type: str
    value: Any
    source: str
    confidence: Confidence = Confidence.unknown
    notes: str = ""


class Entity(BaseModel):
    type: str
    value: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    from_entity: str
    to_entity: str
    relation: str


class Source(BaseModel):
    name: str
    url: str = ""
    queried_at: datetime = Field(default_factory=datetime.utcnow)
    success: bool = True


class Evidence(BaseModel):
    filename: str
    path: str
    description: str = ""


class OsintResult(BaseModel):
    task_id: str = Field(default_factory=lambda: str(uuid4()))
    workflow: str
    status: TaskStatus = TaskStatus.running
    target: str
    target_type: TargetType
    summary: str = ""
    findings: list[Finding] = Field(default_factory=list)
    entities: list[Entity] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    sources: list[Source] = Field(default_factory=list)
    confidence: Confidence = Confidence.unknown
    risk: Risk = Risk.unknown
    evidence: list[Evidence] = Field(default_factory=list)
    raw_output_path: str = ""
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    warnings: list[str] = Field(default_factory=list)


class WorkflowRequest(BaseModel):
    workflow: str
    target: str
    mode: str = "safe"
    output_format: str = "json"
    # Flat fields for person_recon (GPT Actions doesn't support nested objects)
    location: str = ""
    company: str = ""
    email: str = ""
    phone: str = ""
    options: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        # Merge flat fields into options so orchestrator can read them uniformly
        for key in ("location", "company", "email", "phone"):
            val = getattr(self, key, "")
            if val and key not in self.options:
                self.options[key] = val


class ReportRequest(BaseModel):
    task_id: str
    format: str = "markdown"
