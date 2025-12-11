"""
Worker Queue with Rate Limiting

Features:
- Async task queue for scan jobs
- Per-CIDR rate limiting
- Exponential backoff on failures
- Dead letter queue for poison messages
- Graceful shutdown with queue draining
"""

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine

from src.logger import get_logger

logger = get_logger(__name__)


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


@dataclass
class Task:
    """Represents a scan task."""
    id: str
    target: str
    cidr: str
    payload: dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    attempts: int = 0
    max_attempts: int = 3
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    result: Any | None = None


class RateLimiter:
    """
    Per-CIDR rate limiting with sliding window.
    
    Enforces max requests per minute per /24 network.
    """
    
    def __init__(
        self,
        max_per_minute: int = 10,
        cooldown_multiplier: float = 2.0,
        window_seconds: int = 60
    ):
        self._max_per_minute = max_per_minute
        self._cooldown_multiplier = cooldown_multiplier
        self._window = window_seconds
        self._requests: dict[str, list[datetime]] = defaultdict(list)
        self._cooldowns: dict[str, datetime] = {}
    
    def allow(self, cidr: str) -> bool:
        """Check if request is allowed for this CIDR."""
        now = datetime.now(timezone.utc)
        
        # Check cooldown
        if cidr in self._cooldowns:
            if now < self._cooldowns[cidr]:
                return False
            del self._cooldowns[cidr]
        
        # Clean old requests
        cutoff = now.timestamp() - self._window
        self._requests[cidr] = [
            t for t in self._requests[cidr]
            if t.timestamp() > cutoff
        ]
        
        # Check limit
        if len(self._requests[cidr]) >= self._max_per_minute:
            return False
        
        # Record request
        self._requests[cidr].append(now)
        return True
    
    def apply_cooldown(self, cidr: str, base_delay: float = 60.0) -> None:
        """Apply exponential cooldown after failure."""
        now = datetime.now(timezone.utc)
        delay = base_delay * self._cooldown_multiplier
        self._cooldowns[cidr] = datetime.fromtimestamp(
            now.timestamp() + delay,
            tz=timezone.utc
        )
        logger.warning(
            "rate_limit_cooldown",
            cidr=cidr,
            delay_seconds=delay
        )
    
    def get_wait_time(self, cidr: str) -> float:
        """Get seconds to wait before next request."""
        now = datetime.now(timezone.utc)
        
        # Check cooldown first
        if cidr in self._cooldowns:
            return max(0, (self._cooldowns[cidr] - now).total_seconds())
        
        # Check rate limit
        if not self._requests[cidr]:
            return 0
        
        oldest = min(self._requests[cidr])
        next_available = oldest.timestamp() + self._window
        return max(0, next_available - now.timestamp())


class ScanQueue:
    """
    Async task queue for scan jobs.
    
    Features:
    - Worker pool with configurable size
    - Per-CIDR rate limiting
    - Retry with exponential backoff
    - Dead letter queue for failed tasks
    - Graceful shutdown
    """
    
    def __init__(
        self,
        num_workers: int = 5,
        max_per_minute_per_cidr: int = 10,
        max_attempts: int = 3,
    ):
        self._num_workers = num_workers
        self._max_attempts = max_attempts
        self._rate_limiter = RateLimiter(max_per_minute=max_per_minute_per_cidr)
        
        self._pending: asyncio.Queue[Task] = asyncio.Queue()
        self._dead_letter: asyncio.Queue[Task] = asyncio.Queue()
        self._active_tasks: dict[str, Task] = {}
        
        self._workers: list[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()
        self._handler: Callable[[Task], Coroutine[Any, Any, Any]] | None = None
    
    def set_handler(
        self,
        handler: Callable[[Task], Coroutine[Any, Any, Any]]
    ) -> None:
        """Set the task handler function."""
        self._handler = handler
    
    async def submit(
        self,
        task_id: str,
        target: str,
        cidr: str,
        payload: dict[str, Any]
    ) -> Task:
        """Submit a new task to the queue."""
        task = Task(
            id=task_id,
            target=target,
            cidr=cidr,
            payload=payload,
            max_attempts=self._max_attempts
        )
        await self._pending.put(task)
        logger.info("task_submitted", task_id=task_id, target=target)
        return task
    
    async def start(self) -> None:
        """Start worker pool."""
        if not self._handler:
            raise RuntimeError("Task handler not set. Call set_handler() first.")
        
        self._shutdown_event.clear()
        self._workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self._num_workers)
        ]
        logger.info("queue_started", workers=self._num_workers)
    
    async def stop(self, drain: bool = True, timeout: float = 30.0) -> None:
        """
        Stop worker pool.
        
        Args:
            drain: If True, wait for pending tasks to complete
            timeout: Max seconds to wait for drain
        """
        logger.info("queue_stopping", drain=drain)
        
        if drain:
            try:
                await asyncio.wait_for(
                    self._drain_queue(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning("queue_drain_timeout")
        
        self._shutdown_event.set()
        
        # Cancel workers
        for worker in self._workers:
            worker.cancel()
        
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        
        logger.info(
            "queue_stopped",
            pending=self._pending.qsize(),
            dead_letter=self._dead_letter.qsize()
        )
    
    async def _drain_queue(self) -> None:
        """Wait for pending queue to empty."""
        while not self._pending.empty() or self._active_tasks:
            await asyncio.sleep(0.5)
    
    async def _worker(self, worker_id: int) -> None:
        """Worker coroutine that processes tasks."""
        logger.debug("worker_started", worker_id=worker_id)
        
        while not self._shutdown_event.is_set():
            try:
                # Get task with timeout to check shutdown
                try:
                    task = await asyncio.wait_for(
                        self._pending.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Rate limit check
                wait_time = self._rate_limiter.get_wait_time(task.cidr)
                if wait_time > 0:
                    logger.debug(
                        "rate_limit_wait",
                        task_id=task.id,
                        cidr=task.cidr,
                        wait_seconds=wait_time
                    )
                    await asyncio.sleep(wait_time)
                
                if not self._rate_limiter.allow(task.cidr):
                    # Re-queue task
                    await self._pending.put(task)
                    continue
                
                # Process task
                await self._process_task(task)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("worker_error", worker_id=worker_id, error=str(e))
        
        logger.debug("worker_stopped", worker_id=worker_id)
    
    async def _process_task(self, task: Task) -> None:
        """Process a single task with retry logic."""
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now(timezone.utc)
        task.attempts += 1
        self._active_tasks[task.id] = task
        
        logger.info(
            "task_processing",
            task_id=task.id,
            target=task.target,
            attempt=task.attempts
        )
        
        try:
            result = await self._handler(task)
            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now(timezone.utc)
            
            logger.info("task_completed", task_id=task.id, target=task.target)
            
        except Exception as e:
            task.error = str(e)
            
            if task.attempts >= task.max_attempts:
                # Move to dead letter queue
                task.status = TaskStatus.DEAD_LETTER
                await self._dead_letter.put(task)
                self._rate_limiter.apply_cooldown(task.cidr)
                
                logger.error(
                    "task_dead_letter",
                    task_id=task.id,
                    target=task.target,
                    attempts=task.attempts,
                    error=str(e)
                )
            else:
                # Retry with backoff
                task.status = TaskStatus.PENDING
                backoff = 2 ** task.attempts  # Exponential backoff
                await asyncio.sleep(backoff)
                await self._pending.put(task)
                
                logger.warning(
                    "task_retry",
                    task_id=task.id,
                    target=task.target,
                    attempt=task.attempts,
                    backoff=backoff,
                    error=str(e)
                )
        
        finally:
            self._active_tasks.pop(task.id, None)
    
    def get_dead_letter_tasks(self) -> list[Task]:
        """Get all tasks in dead letter queue."""
        tasks = []
        while not self._dead_letter.empty():
            try:
                tasks.append(self._dead_letter.get_nowait())
            except asyncio.QueueEmpty:
                break
        return tasks
    
    def get_stats(self) -> dict[str, Any]:
        """Get queue statistics."""
        return {
            "pending": self._pending.qsize(),
            "active": len(self._active_tasks),
            "dead_letter": self._dead_letter.qsize(),
            "workers": len(self._workers),
        }
