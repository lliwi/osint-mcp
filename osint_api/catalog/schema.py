from __future__ import annotations

from pydantic import BaseModel, Field


class ToolEntry(BaseModel):
    name: str
    category: str
    type: str
    binary: str = ""
    enabled: bool = True
    requires_api_key: bool = False
    risk_level: str = "low"
    description: str = ""
    inputs: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)
    parser: str = ""
    timeout: int = 60
    allowed_args: list[str] = Field(default_factory=list)
    source: str = "local"
