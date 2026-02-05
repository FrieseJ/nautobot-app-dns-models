"""Timing attack mitigation for zone transfer service.

Provides response time normalization to prevent timing-based attacks that could
enumerate valid TSIG keys or determine zone authorization by measuring response times.
"""

import asyncio
import logging
import random
import time
from typing import Optional

logger = logging.getLogger(__name__)


class ResponseTimeNormalizer:
    """Normalizes response times to prevent timing attacks.

    Timing attacks can reveal information by measuring how long operations take:
    - Valid vs invalid TSIG keys (HMAC computation time)
    - Authorized vs unauthorized zones (database lookup time)
    - Existing vs non-existing zones

    This class adds a minimum delay and random jitter to all responses,
    making timing analysis ineffective.
    """

    def __init__(
        self,
        enabled: bool = False,
        min_response_time_ms: float = 50.0,
        jitter_ms: float = 10.0
    ):
        """Initialize response time normalizer.

        Args:
            enabled: Whether timing normalization is enabled
            min_response_time_ms: Minimum response time in milliseconds
            jitter_ms: Maximum random jitter in milliseconds
        """
        self.enabled = enabled
        self.min_response_time_ms = min_response_time_ms
        self.jitter_ms = jitter_ms

        if enabled:
            logger.info(
                f"Response time normalization enabled: "
                f"min={min_response_time_ms}ms, jitter=0-{jitter_ms}ms"
            )

    async def normalize(self, start_time: float, operation_name: str = "operation"):
        """Add delay to normalize response time.

        Args:
            start_time: Time when operation started (from time.perf_counter())
            operation_name: Name of the operation for logging
        """
        if not self.enabled:
            return

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Calculate delay needed to reach minimum response time
        target_time_ms = self.min_response_time_ms + random.uniform(0, self.jitter_ms)
        delay_ms = max(0, target_time_ms - elapsed_ms)

        if delay_ms > 0:
            logger.debug(
                f"Normalizing {operation_name} response time: "
                f"elapsed={elapsed_ms:.2f}ms, adding={delay_ms:.2f}ms, "
                f"target={target_time_ms:.2f}ms"
            )
            await asyncio.sleep(delay_ms / 1000.0)
        else:
            logger.debug(
                f"{operation_name} response time already normalized: "
                f"elapsed={elapsed_ms:.2f}ms >= target={target_time_ms:.2f}ms"
            )


class TimingContext:
    """Context manager for timing-attack-resistant operations.

    Usage:
        async with TimingContext(normalizer) as ctx:
            # Do work
            result = process_request()
        # Timing normalization happens here
    """

    def __init__(
        self,
        normalizer: ResponseTimeNormalizer,
        operation_name: str = "operation"
    ):
        """Initialize timing context.

        Args:
            normalizer: ResponseTimeNormalizer instance
            operation_name: Name of the operation for logging
        """
        self.normalizer = normalizer
        self.operation_name = operation_name
        self.start_time = None

    async def __aenter__(self):
        """Enter context and start timing."""
        self.start_time = time.perf_counter()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit context and normalize timing."""
        if self.start_time is not None:
            await self.normalizer.normalize(self.start_time, self.operation_name)
        return False  # Don't suppress exceptions


def get_timing_settings():
    """Get timing normalization settings from constance config.

    Returns:
        Dictionary with timing settings
    """
    try:
        from constance import config as constance_config
        return {
            "enabled": getattr(constance_config, "ZONE_TRANSFER_NORMALIZE_TIMING", False),
            "min_response_time_ms": getattr(constance_config, "ZONE_TRANSFER_MIN_RESPONSE_TIME_MS", 50),
            "jitter_ms": getattr(constance_config, "ZONE_TRANSFER_TIMING_JITTER_MS", 10),
        }
    except ImportError:
        # Fallback to defaults if constance not available (testing)
        return {
            "enabled": False,
            "min_response_time_ms": 50,
            "jitter_ms": 10,
        }


def create_normalizer_from_settings() -> ResponseTimeNormalizer:
    """Create a ResponseTimeNormalizer from constance settings.

    Returns:
        Configured ResponseTimeNormalizer instance
    """
    settings = get_timing_settings()
    return ResponseTimeNormalizer(
        enabled=settings["enabled"],
        min_response_time_ms=settings["min_response_time_ms"],
        jitter_ms=settings["jitter_ms"]
    )


# Global normalizer instance (initialized by server)
_normalizer_instance: Optional[ResponseTimeNormalizer] = None


def get_normalizer() -> ResponseTimeNormalizer:
    """Get the global timing normalizer instance.

    Returns:
        ResponseTimeNormalizer instance (may be disabled)
    """
    global _normalizer_instance
    if _normalizer_instance is None:
        _normalizer_instance = create_normalizer_from_settings()
    return _normalizer_instance


def initialize_normalizer(
    enabled: bool = False,
    min_response_time_ms: float = 50.0,
    jitter_ms: float = 10.0
) -> ResponseTimeNormalizer:
    """Initialize the global timing normalizer instance.

    Args:
        enabled: Whether timing normalization is enabled
        min_response_time_ms: Minimum response time in milliseconds
        jitter_ms: Maximum random jitter in milliseconds

    Returns:
        Initialized ResponseTimeNormalizer instance
    """
    global _normalizer_instance
    _normalizer_instance = ResponseTimeNormalizer(
        enabled=enabled,
        min_response_time_ms=min_response_time_ms,
        jitter_ms=jitter_ms
    )
    return _normalizer_instance
