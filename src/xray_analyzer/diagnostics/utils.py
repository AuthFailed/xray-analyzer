"""Common utilities for diagnostic checks."""

import asyncio
from contextlib import asynccontextmanager
from typing import Any


@asynccontextmanager
async def measure_duration():
    """
    Async context manager that measures execution time.

    Usage:
        async with measure_duration() as timing:
            await some_operation()
            # timing["duration_ms"] is available after the block

    After the block exits, timing["duration_ms"] contains the elapsed time in milliseconds.
    """
    start = asyncio.get_running_loop().time()
    timing: dict[str, Any] = {"duration_ms": 0.0}
    try:
        yield timing
    finally:
        timing["duration_ms"] = round((asyncio.get_running_loop().time() - start) * 1000, 2)
