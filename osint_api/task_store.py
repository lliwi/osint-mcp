"""
In-memory async task store. Maps task_id → task state + OsintResult.
Thread-safe via asyncio.Lock.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from uuid import uuid4

from mcp_server.schemas.common import OsintResult, TaskStatus

logger = logging.getLogger(__name__)


class TaskRecord:
    __slots__ = ("task_id", "workflow", "target", "status", "result", "started_at", "finished_at", "error")

    def __init__(self, task_id: str, workflow: str, target: str) -> None:
        self.task_id = task_id
        self.workflow = workflow
        self.target = target
        self.status = TaskStatus.running
        self.result: OsintResult | None = None
        self.started_at: datetime = datetime.utcnow()
        self.finished_at: datetime | None = None
        self.error: str = ""


class TaskStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._tasks: dict[str, TaskRecord] = {}

    def new_task_id(self) -> str:
        return str(uuid4())

    async def create(self, workflow: str, target: str) -> TaskRecord:
        task_id = self.new_task_id()
        record = TaskRecord(task_id=task_id, workflow=workflow, target=target)
        async with self._lock:
            self._tasks[task_id] = record
        logger.info("Task created: %s (%s → %s)", task_id, workflow, target)
        return record

    async def complete(self, task_id: str, result: OsintResult) -> None:
        async with self._lock:
            record = self._tasks.get(task_id)
            if record:
                record.status = TaskStatus.completed
                record.result = result
                record.finished_at = datetime.utcnow()
                logger.info("Task completed: %s", task_id)

    async def fail(self, task_id: str, error: str) -> None:
        async with self._lock:
            record = self._tasks.get(task_id)
            if record:
                record.status = TaskStatus.failed
                record.error = error
                record.finished_at = datetime.utcnow()
                logger.error("Task failed: %s — %s", task_id, error)

    async def get(self, task_id: str) -> TaskRecord | None:
        async with self._lock:
            return self._tasks.get(task_id)

    async def list_all(self) -> list[TaskRecord]:
        async with self._lock:
            return list(self._tasks.values())


# Singleton store shared across the application
task_store = TaskStore()
