from __future__ import annotations

import json

from mcp_server.schemas.common import OsintResult


def build_json_report(result: OsintResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False)
