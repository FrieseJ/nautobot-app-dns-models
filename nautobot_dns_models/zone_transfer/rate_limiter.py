"""Rate limiting for zone transfer service to prevent DoS attacks.

Implements per-IP and global connection/request rate limiting with sliding window algorithm.
"""

import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class RateLimiter:
    """Thread-safe rate limiter for zone transfer requests.

    Tracks request rates per IP address and enforces limits to prevent DoS attacks.
    Uses sliding window algorithm for accurate rate limiting.
    """

    def __init__(
        self,
        requests_per_ip: int = 10,
        window_seconds: int = 60,
        max_connections_per_ip: int = 3,
        max_connections_global: int = 100,
    ):
        """Initialize rate limiter.

        Args:
            requests_per_ip: Maximum requests allowed per IP in the window
            window_seconds: Time window for rate limiting in seconds
            max_connections_per_ip: Maximum concurrent connections per IP
            max_connections_global: Maximum concurrent connections globally
        """
        self.requests_per_ip = requests_per_ip
        self.window_seconds = window_seconds
        self.max_connections_per_ip = max_connections_per_ip
        self.max_connections_global = max_connections_global

        # Track request timestamps per IP (sliding window)
        self._request_history: Dict[str, list] = defaultdict(list)

        # Track active connections
        self._active_connections: Dict[str, int] = defaultdict(int)
        self._total_connections: int = 0

        # Thread safety
        self._lock = Lock()

        logger.info(
            f"Rate limiter initialized: {requests_per_ip} req/{window_seconds}s per IP, "
            f"{max_connections_per_ip} conn/IP, {max_connections_global} conn global"
        )

    def check_request_rate(self, ip_address: str) -> Tuple[bool, str]:
        """Check if a request from the given IP is within rate limits.

        Args:
            ip_address: Source IP address

        Returns:
            Tuple of (allowed: bool, reason: str)
            - (True, "") if allowed
            - (False, reason) if denied with explanation
        """
        with self._lock:
            now = time.time()
            cutoff_time = now - self.window_seconds

            # Clean up old request timestamps (outside the window)
            if ip_address in self._request_history:
                self._request_history[ip_address] = [
                    ts for ts in self._request_history[ip_address]
                    if ts > cutoff_time
                ]

            # Check rate limit
            request_count = len(self._request_history[ip_address])
            if request_count >= self.requests_per_ip:
                logger.warning(
                    f"Rate limit exceeded for {ip_address}: "
                    f"{request_count} requests in {self.window_seconds}s "
                    f"(limit: {self.requests_per_ip})"
                )
                return (
                    False,
                    f"Rate limit exceeded: {request_count}/{self.requests_per_ip} requests in {self.window_seconds}s"
                )

            # Record this request
            self._request_history[ip_address].append(now)

            logger.debug(
                f"Request rate check passed for {ip_address}: "
                f"{request_count + 1}/{self.requests_per_ip}"
            )
            return (True, "")

    def check_connection_limit(self, ip_address: str) -> Tuple[bool, str]:
        """Check if a new connection from the given IP is within limits.

        Args:
            ip_address: Source IP address

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        with self._lock:
            # Check per-IP connection limit
            ip_connections = self._active_connections.get(ip_address, 0)
            if ip_connections >= self.max_connections_per_ip:
                logger.warning(
                    f"Per-IP connection limit exceeded for {ip_address}: "
                    f"{ip_connections}/{self.max_connections_per_ip}"
                )
                return (
                    False,
                    f"Too many concurrent connections from {ip_address}: "
                    f"{ip_connections}/{self.max_connections_per_ip}"
                )

            # Check global connection limit
            if self._total_connections >= self.max_connections_global:
                logger.warning(
                    f"Global connection limit exceeded: "
                    f"{self._total_connections}/{self.max_connections_global}"
                )
                return (
                    False,
                    f"Server at maximum capacity: "
                    f"{self._total_connections}/{self.max_connections_global} connections"
                )

            return (True, "")

    def acquire_connection(self, ip_address: str) -> bool:
        """Acquire a connection slot for the given IP.

        Must be called after check_connection_limit() succeeds.
        Must be paired with release_connection() when done.

        Args:
            ip_address: Source IP address

        Returns:
            True if acquired, False if limits exceeded
        """
        with self._lock:
            # Double-check limits
            allowed, _ = self.check_connection_limit(ip_address)
            if not allowed:
                return False

            # Increment counters
            self._active_connections[ip_address] += 1
            self._total_connections += 1

            logger.debug(
                f"Connection acquired for {ip_address}: "
                f"{self._active_connections[ip_address]} from IP, "
                f"{self._total_connections} global"
            )
            return True

    def release_connection(self, ip_address: str):
        """Release a connection slot for the given IP.

        Args:
            ip_address: Source IP address
        """
        with self._lock:
            if ip_address in self._active_connections:
                self._active_connections[ip_address] -= 1
                if self._active_connections[ip_address] <= 0:
                    del self._active_connections[ip_address]

            self._total_connections = max(0, self._total_connections - 1)

            logger.debug(
                f"Connection released for {ip_address}: "
                f"{self._active_connections.get(ip_address, 0)} from IP, "
                f"{self._total_connections} global"
            )

    def get_stats(self) -> dict:
        """Get current rate limiter statistics.

        Returns:
            Dictionary with rate limiter stats
        """
        with self._lock:
            return {
                "total_connections": self._total_connections,
                "tracked_ips": len(self._active_connections),
                "connections_by_ip": dict(self._active_connections),
                "config": {
                    "requests_per_ip": self.requests_per_ip,
                    "window_seconds": self.window_seconds,
                    "max_connections_per_ip": self.max_connections_per_ip,
                    "max_connections_global": self.max_connections_global,
                },
            }

    def reset(self):
        """Reset all rate limiting state (for testing)."""
        with self._lock:
            self._request_history.clear()
            self._active_connections.clear()
            self._total_connections = 0
            logger.info("Rate limiter state reset")


# Global rate limiter instance (initialized by server)
_rate_limiter_instance = None


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance.

    Returns:
        RateLimiter instance

    Raises:
        RuntimeError: If rate limiter not initialized
    """
    if _rate_limiter_instance is None:
        raise RuntimeError("Rate limiter not initialized. Call initialize_rate_limiter() first.")
    return _rate_limiter_instance


def initialize_rate_limiter(
    requests_per_ip: int = 10,
    window_seconds: int = 60,
    max_connections_per_ip: int = 3,
    max_connections_global: int = 100,
) -> RateLimiter:
    """Initialize the global rate limiter instance.

    Args:
        requests_per_ip: Maximum requests per IP in window
        window_seconds: Rate limit window in seconds
        max_connections_per_ip: Max concurrent connections per IP
        max_connections_global: Max concurrent connections globally

    Returns:
        Initialized RateLimiter instance
    """
    global _rate_limiter_instance
    _rate_limiter_instance = RateLimiter(
        requests_per_ip=requests_per_ip,
        window_seconds=window_seconds,
        max_connections_per_ip=max_connections_per_ip,
        max_connections_global=max_connections_global,
    )
    return _rate_limiter_instance
