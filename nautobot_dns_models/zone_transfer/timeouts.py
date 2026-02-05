"""Timeout utilities for zone transfer operations.

Provides timeout wrappers and decorators to prevent resource exhaustion attacks.
"""

import asyncio
import logging
from functools import wraps
from typing import TypeVar, Callable, Any

logger = logging.getLogger(__name__)

T = TypeVar('T')


class TimeoutError(Exception):
    """Raised when an operation exceeds its timeout."""
    pass


async def with_timeout(coro, timeout_seconds: float, operation_name: str = "operation"):
    """Execute a coroutine with a timeout.

    Args:
        coro: Coroutine to execute
        timeout_seconds: Timeout in seconds
        operation_name: Name of the operation for logging

    Returns:
        Result of the coroutine

    Raises:
        TimeoutError: If the operation exceeds the timeout
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(f"{operation_name} exceeded timeout of {timeout_seconds}s")
        raise TimeoutError(f"{operation_name} timed out after {timeout_seconds} seconds")


def timeout_decorator(timeout_seconds: float, operation_name: str = None):
    """Decorator to add timeout to async functions.

    Args:
        timeout_seconds: Timeout in seconds
        operation_name: Optional operation name for logging (defaults to function name)

    Example:
        @timeout_decorator(5.0, "TSIG validation")
        async def validate_tsig(message, key):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            op_name = operation_name or func.__name__
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=timeout_seconds
                )
            except asyncio.TimeoutError:
                logger.warning(f"{op_name} exceeded timeout of {timeout_seconds}s")
                raise TimeoutError(f"{op_name} timed out after {timeout_seconds} seconds")
        return wrapper
    return decorator


class ConnectionTimeoutManager:
    """Manages connection timeouts (idle and total)."""

    def __init__(self, idle_timeout: float, total_timeout: float = None):
        """Initialize timeout manager.

        Args:
            idle_timeout: Seconds before closing idle connection
            total_timeout: Optional maximum total connection time
        """
        self.idle_timeout = idle_timeout
        self.total_timeout = total_timeout
        self._last_activity = asyncio.get_event_loop().time()
        self._connection_start = self._last_activity
        self._timeout_task = None

    def update_activity(self):
        """Update last activity timestamp."""
        self._last_activity = asyncio.get_event_loop().time()

    def get_idle_time(self) -> float:
        """Get seconds since last activity."""
        return asyncio.get_event_loop().time() - self._last_activity

    def get_total_time(self) -> float:
        """Get total connection duration in seconds."""
        return asyncio.get_event_loop().time() - self._connection_start

    def check_idle_timeout(self) -> bool:
        """Check if connection has exceeded idle timeout.

        Returns:
            True if timed out, False otherwise
        """
        if self.get_idle_time() > self.idle_timeout:
            logger.info(f"Connection idle timeout: {self.get_idle_time():.1f}s > {self.idle_timeout}s")
            return True
        return False

    def check_total_timeout(self) -> bool:
        """Check if connection has exceeded total timeout.

        Returns:
            True if timed out (and total_timeout is set), False otherwise
        """
        if self.total_timeout and self.get_total_time() > self.total_timeout:
            logger.info(f"Connection total timeout: {self.get_total_time():.1f}s > {self.total_timeout}s")
            return True
        return False

    async def start_idle_monitor(self, callback: Callable):
        """Start monitoring for idle timeout.

        Args:
            callback: Async function to call when idle timeout occurs
        """
        while True:
            await asyncio.sleep(1)  # Check every second
            if self.check_idle_timeout():
                await callback()
                break
            if self.total_timeout and self.check_total_timeout():
                await callback()
                break


def get_timeout_settings():
    """Get timeout settings from constance config.

    Returns:
        Dictionary with timeout values in seconds
    """
    try:
        from constance import config as constance_config
        return {
            "conn_timeout": getattr(constance_config, "ZONE_TRANSFER_CONN_TIMEOUT", 10),
            "idle_timeout": getattr(constance_config, "ZONE_TRANSFER_IDLE_TIMEOUT", 30),
            "operation_timeout": getattr(constance_config, "ZONE_TRANSFER_OPERATION_TIMEOUT", 30),
            "db_timeout": getattr(constance_config, "ZONE_TRANSFER_DB_TIMEOUT", 10),
        }
    except ImportError:
        # Fallback to defaults if constance not available (testing)
        return {
            "conn_timeout": 10,
            "idle_timeout": 30,
            "operation_timeout": 30,
            "db_timeout": 10,
        }
