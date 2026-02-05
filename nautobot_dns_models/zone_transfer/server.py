"""DNS Zone Transfer Server.

Provides TCP and UDP listeners for zone transfer requests with async request handling.
"""

import asyncio
import logging
import time
from typing import Tuple, Optional

import dns.message
import dns.rcode

from .handler import ZoneTransferHandler
from .rate_limiter import RateLimiter
from .timeouts import with_timeout, TimeoutError, get_timeout_settings
from .timing import ResponseTimeNormalizer

logger = logging.getLogger(__name__)


class ZoneTransferServer:
    """Async DNS server for zone transfers.

    Listens on both TCP and UDP (zone transfers typically use TCP but we support both).
    """

    def __init__(
        self,
        bind_address: str = "0.0.0.0",
        port: int = 5353,
        rate_limiter: Optional[RateLimiter] = None,
        timing_normalizer: Optional[ResponseTimeNormalizer] = None
    ):
        """Initialize the zone transfer server.

        Args:
            bind_address: IP address to bind to (default: 0.0.0.0 for all interfaces)
            port: Port to listen on (default: 5353, non-privileged DNS port)
            rate_limiter: RateLimiter instance (optional, for DoS protection)
            timing_normalizer: ResponseTimeNormalizer instance (optional, for timing attack mitigation)
        """
        self.bind_address = bind_address
        self.port = port
        self.rate_limiter = rate_limiter
        self.timing_normalizer = timing_normalizer or ResponseTimeNormalizer(enabled=False)
        self.tcp_server = None
        self.udp_transport = None
        self.udp_protocol = None
        self._shutdown_event = asyncio.Event()

    async def start(self):
        """Start the TCP and UDP servers."""
        import sys
        print(f">>> server.start() ENTERED - bind={self.bind_address}:{self.port}", file=sys.stderr)
        logger.info(f"Starting zone transfer server on {self.bind_address}:{self.port}")

        # Start TCP server
        print(f">>> server.start(): About to call asyncio.start_server()...", file=sys.stderr)
        self.tcp_server = await asyncio.start_server(
            self._handle_tcp_client,
            self.bind_address,
            self.port,
        )
        print(f">>> server.start(): TCP server created: {self.tcp_server}", file=sys.stderr)
        print(f">>> server.start(): TCP server is_serving: {self.tcp_server.is_serving()}", file=sys.stderr)
        print(f">>> server.start(): TCP server sockets: {self.tcp_server.sockets}", file=sys.stderr)
        logger.info(f"TCP listener started on {self.bind_address}:{self.port}")

        # Start UDP server
        print(f">>> server.start(): About to create UDP endpoint...", file=sys.stderr)
        loop = asyncio.get_event_loop()
        self.udp_transport, self.udp_protocol = await loop.create_datagram_endpoint(
            lambda: UDPServerProtocol(self._handle_udp_request),
            local_addr=(self.bind_address, self.port),
        )
        print(f">>> server.start(): UDP endpoint created: transport={self.udp_transport}", file=sys.stderr)
        logger.info(f"UDP listener started on {self.bind_address}:{self.port}")

        print(f">>> server.start(): COMPLETED SUCCESSFULLY", file=sys.stderr)
        logger.info("Zone transfer server started successfully")

    async def serve_forever(self):
        """Run the server until shutdown is requested."""
        import sys
        print(">>> serve_forever() ENTERED", file=sys.stderr)
        print(f">>> TCP server is_serving: {self.tcp_server.is_serving() if self.tcp_server else 'None'}", file=sys.stderr)
        print(f">>> UDP transport: {self.udp_transport}", file=sys.stderr)

        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            logger.info("Server cancelled, shutting down")
        finally:
            await self.stop()

    async def stop(self):
        """Stop the TCP and UDP servers gracefully."""
        logger.info("Stopping zone transfer server")

        # Stop TCP server
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
            logger.info("TCP server stopped")

        # Stop UDP server
        if self.udp_transport:
            self.udp_transport.close()
            logger.info("UDP server stopped")

        logger.info("Zone transfer server stopped")

    def shutdown(self):
        """Signal the server to shut down."""
        self._shutdown_event.set()

    async def _handle_tcp_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """Handle a single TCP client connection.

        TCP DNS messages are prefixed with a 2-byte length field (RFC 1035 §4.2.2).

        Args:
            reader: asyncio.StreamReader for reading from client
            writer: asyncio.StreamWriter for writing to client
        """
        import sys
        print(">>> _handle_tcp_client() CALLED - new TCP connection!", file=sys.stderr)
        addr = writer.get_extra_info('peername')
        source_ip, source_port = addr[0], addr[1]
        print(f">>> TCP connection from {source_ip}:{source_port}", file=sys.stderr)
        logger.info(f"TCP connection from {source_ip}:{source_port}")

        print(f">>> About to check rate limiter (enabled: {self.rate_limiter is not None})", file=sys.stderr)
        # Check connection limits if rate limiter is enabled
        if self.rate_limiter:
            # Run in thread pool to avoid blocking event loop
            loop = asyncio.get_event_loop()
            allowed, reason = await loop.run_in_executor(
                None,
                self.rate_limiter.check_connection_limit,
                source_ip
            )
            print(f">>> check_connection_limit returned: allowed={allowed}, reason={reason}", file=sys.stderr)
            if not allowed:
                logger.warning(f"Connection rejected from {source_ip}:{source_port}: {reason}")
                # Send REFUSED response and close
                try:
                    error_response = self._build_refused_response()
                    length_prefix = len(error_response).to_bytes(2, 'big')
                    writer.write(length_prefix + error_response)
                    await writer.drain()
                except Exception:
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()
                return

            # Acquire connection slot
            print(f">>> Acquiring connection slot for {source_ip}", file=sys.stderr)
            try:
                # Run in thread pool to avoid blocking event loop
                loop = asyncio.get_event_loop()
                acquired = await asyncio.wait_for(
                    loop.run_in_executor(None, self.rate_limiter.acquire_connection, source_ip),
                    timeout=2.0
                )
                print(f">>> acquire_connection returned: {acquired}", file=sys.stderr)
                if not acquired:
                    logger.warning(f"Failed to acquire connection slot for {source_ip}:{source_port}")
                    print(f">>> Connection slot acquisition FAILED", file=sys.stderr)
                    writer.close()
                    await writer.wait_closed()
                    return
                print(f">>> Connection slot acquired successfully", file=sys.stderr)
            except asyncio.TimeoutError:
                print(f">>> TIMEOUT in acquire_connection after 2s!", file=sys.stderr)
                logger.error(f"Timeout acquiring connection slot for {source_ip}")
                writer.close()
                await writer.wait_closed()
                return
            except Exception as e:
                print(f">>> EXCEPTION in acquire_connection: {e}", file=sys.stderr)
                logger.error(f"Error acquiring connection slot: {e}", exc_info=True)
                writer.close()
                await writer.wait_closed()
                return

        print(f">>> Getting timeout settings...", file=sys.stderr)
        # Get timeout settings
        timeout_settings = get_timeout_settings()
        conn_timeout = timeout_settings["conn_timeout"]
        idle_timeout = timeout_settings["idle_timeout"]
        print(f">>> Timeout settings: conn={conn_timeout}, idle={idle_timeout}", file=sys.stderr)

        print(f">>> Entering try block to read DNS query...", file=sys.stderr)
        try:
            # Read the 2-byte length prefix with timeout
            print(f">>> About to read 2-byte length prefix from {source_ip}:{source_port}...", file=sys.stderr)
            read_task = reader.readexactly(2)
            length_bytes = await with_timeout(
                read_task,
                conn_timeout,
                f"Connection from {source_ip}:{source_port}"
            )
            message_length = int.from_bytes(length_bytes, 'big')
            print(f">>> Read length prefix: {message_length} bytes expected", file=sys.stderr)

            # Read the DNS message with idle timeout
            print(f">>> About to read {message_length} bytes of DNS message...", file=sys.stderr)
            read_task = reader.readexactly(message_length)
            request_data = await with_timeout(
                read_task,
                idle_timeout,
                f"Read from {source_ip}:{source_port}"
            )

            print(f">>> Received complete DNS message: {message_length} bytes", file=sys.stderr)
            logger.info(f"Received {message_length} bytes from {source_ip}:{source_port}")

            # Start timing for response normalization
            request_start_time = time.perf_counter()

            # Check request rate limit if rate limiter is enabled
            if self.rate_limiter:
                allowed, reason = self.rate_limiter.check_request_rate(source_ip)
                if not allowed:
                    logger.warning(f"Request rate limit exceeded for {source_ip}:{source_port}: {reason}")
                    error_response = self._build_refused_response()
                    length_prefix = len(error_response).to_bytes(2, 'big')
                    writer.write(length_prefix + error_response)
                    await writer.drain()
                    # Normalize timing for error response
                    await self.timing_normalizer.normalize(
                        request_start_time,
                        f"Rate limit error for {source_ip}"
                    )
                    return

            # Process the request (handler has its own timeouts)
            print(f">>> Creating ZoneTransferHandler for {source_ip}:{source_port}...", file=sys.stderr)
            handler = ZoneTransferHandler(source_ip, source_port)

            print(f">>> Calling handler.handle_request() in thread pool...", file=sys.stderr)

            # Run handler in thread pool since it uses Django ORM (sync operations)
            def process_request():
                """Process request in thread pool to allow Django ORM queries."""
                return list(handler.handle_request(request_data))

            loop = asyncio.get_event_loop()
            responses = await loop.run_in_executor(None, process_request)
            print(f">>> Handler returned {len(responses)} response(s)", file=sys.stderr)

            response_count = 0
            for response_data in responses:
                response_count += 1
                # Prefix each response with its length (TCP DNS format)
                response_length = len(response_data)
                length_prefix = response_length.to_bytes(2, 'big')
                writer.write(length_prefix + response_data)
                await writer.drain()
                print(f">>> Sent response #{response_count}: {response_length} bytes", file=sys.stderr)

            # Normalize timing after successful response
            await self.timing_normalizer.normalize(
                request_start_time,
                f"Zone transfer for {source_ip}"
            )

            print(f">>> Completed zone transfer to {source_ip}:{source_port} ({response_count} responses)", file=sys.stderr)
            logger.info(f"Sent {response_count} response(s) to {source_ip}:{source_port}")

        except TimeoutError as e:
            logger.warning(f"Timeout handling connection from {source_ip}:{source_port}: {e}")
        except asyncio.IncompleteReadError:
            logger.warning(f"Incomplete read from {source_ip}:{source_port}")
        except Exception as e:
            logger.error(f"Error handling TCP request from {source_ip}:{source_port}: {e}", exc_info=True)
        finally:
            # Release connection slot if rate limiter is enabled
            if self.rate_limiter:
                self.rate_limiter.release_connection(source_ip)

            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.warning(f"Error closing connection to {source_ip}:{source_port}: {e}")

    async def _handle_udp_request(self, data: bytes, addr: Tuple[str, int]):
        """Handle a single UDP request.

        Args:
            data: Request data bytes
            addr: Tuple of (source_ip, source_port)
        """
        source_ip, source_port = addr
        logger.debug(f"UDP request from {source_ip}:{source_port}, {len(data)} bytes")

        # Check request rate limit if rate limiter is enabled
        if self.rate_limiter:
            allowed, reason = self.rate_limiter.check_request_rate(source_ip)
            if not allowed:
                logger.warning(f"UDP rate limit exceeded for {source_ip}:{source_port}: {reason}")
                # Send REFUSED response
                error_response = self._build_refused_response()
                self.udp_transport.sendto(error_response, addr)
                return

        try:
            # Process the request
            handler = ZoneTransferHandler(source_ip, source_port)

            # Note: AXFR over UDP is not standard and will likely fail for large zones
            # This primarily handles IXFR queries which may fit in a single UDP packet
            for response_data in handler.handle_request(data):
                self.udp_transport.sendto(response_data, addr)
                # Only send first response over UDP (UDP can't handle multi-message AXFR)
                break

            logger.debug(f"Sent UDP response to {source_ip}:{source_port}")

        except Exception as e:
            logger.error(f"Error handling UDP request from {source_ip}:{source_port}: {e}", exc_info=True)

    def _build_refused_response(self) -> bytes:
        """Build a DNS REFUSED error response.

        Returns:
            DNS message bytes with REFUSED rcode
        """
        response = dns.message.Message()
        response.set_rcode(dns.rcode.REFUSED)
        return response.to_wire()


class UDPServerProtocol(asyncio.DatagramProtocol):
    """Protocol handler for UDP server."""

    def __init__(self, handler_callback):
        """Initialize UDP protocol.

        Args:
            handler_callback: Async function to call for each datagram
        """
        self.handler_callback = handler_callback
        self.transport = None

    def connection_made(self, transport):
        """Called when the protocol is connected to a transport."""
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Called when a datagram is received.

        Args:
            data: Received data bytes
            addr: Tuple of (source_ip, source_port)
        """
        # Schedule the handler as a task
        asyncio.create_task(self.handler_callback(data, addr))


async def run_server(
    bind_address: str = "0.0.0.0",
    port: int = 5353,
    rate_limiter: Optional[RateLimiter] = None,
    timing_normalizer: Optional[ResponseTimeNormalizer] = None
):
    """Run the zone transfer server.

    This is the main entry point for the server.

    Args:
        bind_address: IP address to bind to
        port: Port to listen on
        rate_limiter: Optional RateLimiter instance for DoS protection
        timing_normalizer: Optional ResponseTimeNormalizer for timing attack mitigation
    """
    server = ZoneTransferServer(bind_address, port, rate_limiter, timing_normalizer)
    await server.start()

    try:
        await server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    finally:
        await server.stop()
