"""Plugin declaration for nautobot_dns_models."""

import asyncio
import logging
import threading
from importlib import metadata

from nautobot.apps import ConstanceConfigItem, NautobotAppConfig

__version__ = metadata.version(__name__)

logger = logging.getLogger(__name__)

# nautobot.core.cli places preprocessed settings in a nautobot_config module before loading django
# doing this is a hack but it's the only way we can modify the settings before NautobotAppConfig.constance_config is processed
try:
    import nautobot_config as settings

    NAUTOBOT_CONFIG_LOADED = True
except ImportError:
    NAUTOBOT_CONFIG_LOADED = False

constance_additional_fields = {
    "show_dns_panel": [
        "django.forms.fields.ChoiceField",
        {
            "widget": "django.forms.Select",
            "choices": [
                ("always", "Always"),
                ("if_present", "If records are present"),
                ("never", "Never"),
            ],
        },
    ],
    "dns_validation_level": [
        "django.forms.fields.ChoiceField",
        {
            "widget": "django.forms.Select",
            "choices": [
                ("none", "Disabled"),
                ("wire-format", "Wire format"),
            ],
        },
    ],
}

if NAUTOBOT_CONFIG_LOADED:
    # pylint:disable=no-member
    settings.CONSTANCE_ADDITIONAL_FIELDS |= constance_additional_fields


# Zone transfer server lifecycle management
_server_thread = None
_server_instance = None
_server_lock = threading.Lock()


def _start_zone_transfer_server():
    """Start zone transfer server in background thread.

    This function is thread-safe and idempotent. If the server is already
    running, this function does nothing.
    """
    import sys
    global _server_thread, _server_instance

    print("=" * 80, file=sys.stderr)
    print("_start_zone_transfer_server() CALLED", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    with _server_lock:
        # Check if server is already running
        if _server_thread is not None and _server_thread.is_alive():
            logger.warning("Zone Transfer Start: Server already running")
            print("Zone Transfer Start: Already running, skipping", file=sys.stderr)
            return

        logger.info("Zone Transfer Start: Initializing zone transfer server")
        print("Zone Transfer Start: Creating server instance...", file=sys.stderr)

        try:
            # Import here to avoid circular imports and to ensure Django is ready
            from constance import config
            print("Zone Transfer Start: Imported constance config", file=sys.stderr)

            from .zone_transfer.server import ZoneTransferServer
            from .zone_transfer.rate_limiter import RateLimiter
            from .zone_transfer.timing import ResponseTimeNormalizer
            print("Zone Transfer Start: Imported zone_transfer modules", file=sys.stderr)

            # Helper function to get config with fallback to default
            def get_config_value(key, default):
                try:
                    return getattr(config, key)
                except AttributeError:
                    logger.warning(f"Zone Transfer Start: Config key {key} not found, using default: {default}")
                    return default

            # TEMPORARILY DISABLED: Rate limiter has blocking operations incompatible with asyncio
            # TODO: Reimplement rate limiter with async-compatible locking
            rate_limiter = None
            print("Zone Transfer Start: Rate limiter DISABLED (temporarily)", file=sys.stderr)

            # rate_limiter = RateLimiter(
            #     requests_per_ip=get_config_value('ZONE_TRANSFER_RATE_LIMIT_PER_IP', 10),
            #     window_seconds=get_config_value('ZONE_TRANSFER_RATE_LIMIT_WINDOW', 60),
            #     max_connections_per_ip=get_config_value('ZONE_TRANSFER_MAX_CONN_PER_IP', 3),
            #     max_connections_global=get_config_value('ZONE_TRANSFER_MAX_CONN_GLOBAL', 100),
            # )
            # print("Zone Transfer Start: Created rate limiter", file=sys.stderr)

            # Create timing normalizer with config from constance (with fallbacks)
            timing_normalizer = ResponseTimeNormalizer(
                enabled=get_config_value('ZONE_TRANSFER_NORMALIZE_TIMING', False),
                min_response_time_ms=get_config_value('ZONE_TRANSFER_MIN_RESPONSE_TIME_MS', 50),
                jitter_ms=get_config_value('ZONE_TRANSFER_TIMING_JITTER_MS', 10),
            )
            print("Zone Transfer Start: Created timing normalizer", file=sys.stderr)

            # Create server instance
            bind_address = get_config_value('ZONE_TRANSFER_BIND_ADDRESS', '0.0.0.0')
            port = get_config_value('ZONE_TRANSFER_PORT', 5354)

            _server_instance = ZoneTransferServer(
                bind_address=bind_address,
                port=port,
                rate_limiter=rate_limiter,
                timing_normalizer=timing_normalizer,
            )
            print(f"Zone Transfer Start: Created server instance (bind={bind_address}:{port})", file=sys.stderr)

            # Start server in daemon thread
            _server_thread = threading.Thread(
                target=_run_server_thread,
                daemon=True,
                name="zone-transfer-server"
            )
            _server_thread.start()
            print("Zone Transfer Start: Started daemon thread", file=sys.stderr)

            logger.info(
                f"Zone Transfer Start: Server started successfully on {bind_address}:"
                f"{port}"
            )
            print(f"✅ Zone Transfer Server STARTED on {bind_address}:{port}", file=sys.stderr)
        except Exception as e:
            logger.error(f"Zone Transfer Start: Failed to start server: {e}", exc_info=True)
            print(f"❌ Zone Transfer Start ERROR: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            _server_thread = None
            _server_instance = None


def _stop_zone_transfer_server():
    """Stop zone transfer server gracefully.

    This function is thread-safe and idempotent. If the server is not running,
    this function does nothing.
    """
    import sys
    global _server_thread, _server_instance

    print("=" * 80, file=sys.stderr)
    print("_stop_zone_transfer_server() CALLED", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    with _server_lock:
        if _server_instance is None:
            logger.warning("Zone Transfer Stop: Server not running")
            print("Zone Transfer Stop: Server not running, nothing to stop", file=sys.stderr)
            return

        logger.info("Zone Transfer Stop: Stopping zone transfer server")
        print("Zone Transfer Stop: Initiating graceful shutdown...", file=sys.stderr)

        try:
            # Signal shutdown to the server
            _server_instance.shutdown()
            print("Zone Transfer Stop: Called server.shutdown()", file=sys.stderr)

            # Wait for thread to finish (with timeout)
            if _server_thread and _server_thread.is_alive():
                print("Zone Transfer Stop: Waiting for thread to finish (timeout=5s)...", file=sys.stderr)
                _server_thread.join(timeout=5.0)
                if _server_thread.is_alive():
                    logger.warning("Zone Transfer Stop: Thread did not stop within timeout")
                    print("Zone Transfer Stop: WARNING - Thread still alive after timeout", file=sys.stderr)
                else:
                    print("Zone Transfer Stop: Thread finished cleanly", file=sys.stderr)

            logger.info("Zone Transfer Stop: Server stopped successfully")
            print("✅ Zone Transfer Server STOPPED", file=sys.stderr)
        except Exception as e:
            logger.error(f"Zone Transfer Stop: Error stopping server: {e}", exc_info=True)
            print(f"❌ Zone Transfer Stop ERROR: {e}", file=sys.stderr)
        finally:
            _server_thread = None
            _server_instance = None
            print("Zone Transfer Stop: Cleaned up server state", file=sys.stderr)


def _run_server_thread():
    """Thread target that runs the asyncio event loop for the zone transfer server."""
    import sys
    print("=" * 80, file=sys.stderr)
    print("_run_server_thread(): THREAD FUNCTION STARTED", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    try:
        # Create new event loop for this thread
        print("_run_server_thread(): Creating new event loop...", file=sys.stderr)
        loop = asyncio.new_event_loop()
        print(f"_run_server_thread(): Event loop created: {loop}", file=sys.stderr)

        asyncio.set_event_loop(loop)
        print("_run_server_thread(): Event loop set as current", file=sys.stderr)

        # Run server
        print(f"_run_server_thread(): About to call server.start() on instance: {_server_instance}", file=sys.stderr)
        loop.run_until_complete(_server_instance.start())
        print("_run_server_thread(): server.start() completed successfully!", file=sys.stderr)
        print("_run_server_thread(): About to call server.serve_forever()...", file=sys.stderr)
        loop.run_until_complete(_server_instance.serve_forever())
        print("_run_server_thread(): server.serve_forever() completed (should never reach here)", file=sys.stderr)
    except Exception as e:
        logger.error(f"Zone transfer server error: {e}", exc_info=True)
        print(f"❌ _run_server_thread() EXCEPTION: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
    finally:
        print("_run_server_thread(): Entering finally block...", file=sys.stderr)
        try:
            loop.close()
            print("_run_server_thread(): Event loop closed", file=sys.stderr)
        except Exception as e:
            print(f"_run_server_thread(): Error closing loop: {e}", file=sys.stderr)


def _handle_zone_transfer_config_change(sender, key, old_value, new_value, **kwargs):
    """Handle changes to ZONE_TRANSFER_ENABLED setting.

    This signal handler is called when any constance config value changes.
    We filter for ZONE_TRANSFER_ENABLED and start/stop the server accordingly.

    Note: The key from constance includes the full namespace path:
    'constance:nautobot:nautobot_dns_models__ZONE_TRANSFER_ENABLED'
    """
    import sys
    print(f"Zone Transfer Signal: config_updated fired - key={key}, old={old_value}, new={new_value}", file=sys.stderr)

    # Check if this is our ZONE_TRANSFER_ENABLED setting
    # The key includes the full namespace: constance:nautobot:nautobot_dns_models__ZONE_TRANSFER_ENABLED
    if key == "ZONE_TRANSFER_ENABLED" or key.endswith("ZONE_TRANSFER_ENABLED"):
        logger.info(f"Zone Transfer Signal: ZONE_TRANSFER_ENABLED changed from {old_value} to {new_value}")
        print(f"Zone Transfer Signal: DETECTED ZONE_TRANSFER_ENABLED change!", file=sys.stderr)

        if new_value and not old_value:
            # Enabled: Start server
            logger.info("Zone Transfer Signal: Zone transfer enabled, starting server")
            print("Zone Transfer Signal: Calling _start_zone_transfer_server()", file=sys.stderr)
            _start_zone_transfer_server()
        elif old_value and not new_value:
            # Disabled: Stop server
            logger.info("Zone Transfer Signal: Zone transfer disabled, stopping server")
            print("Zone Transfer Signal: Calling _stop_zone_transfer_server()", file=sys.stderr)
            _stop_zone_transfer_server()
        else:
            logger.info(f"Zone Transfer Signal: No action needed (old={old_value}, new={new_value})")
            print(f"Zone Transfer Signal: No action (both={new_value})", file=sys.stderr)


class NautobotDnsModelsConfig(NautobotAppConfig):
    """Plugin configuration for the nautobot_dns_models plugin."""

    name = "nautobot_dns_models"
    verbose_name = "Nautobot DNS Models"
    version = __version__
    author = "Network to Code, LLC"
    description = "Nautobot DNS Models."
    base_url = "dns"
    required_settings = []
    default_settings = {}
    docs_view_name = "plugins:nautobot_dns_models:docs"
    searchable_models = [
        "DNSView",
        "DNSZone",
        "TSIGKey",
        "ZoneTransferACL",
        "ARecord",
        "AAAARecord",
        "PTRRecord",
        "CNAMERecord",
        "NSRecord",
        "MXRecord",
        "SRVRecord",
        "TXTRecord",
    ]

    def ready(self):
        """Initialize the app when Django starts.

        This method is called when Django loads the app. It:
        1. Registers signal handlers for constance config changes
        2. Auto-starts the zone transfer server if enabled on startup
        """
        import sys
        print("=" * 80, file=sys.stderr)
        print("ZONE TRANSFER LIFECYCLE: ready() method called!", file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        super().ready()
        logger.info("Zone Transfer Lifecycle: NautobotDnsModelsConfig.ready() called")

        # Register signal handler for constance config changes
        # Use dispatch_uid to prevent duplicate registrations during testing
        try:
            from constance.signals import config_updated
            config_updated.connect(
                _handle_zone_transfer_config_change,
                dispatch_uid="nautobot_dns_models_zone_transfer_config"
            )
            logger.info("Zone Transfer Lifecycle: Registered constance config_updated signal handler")
            print("Zone Transfer: Signal handler registered successfully", file=sys.stderr)
        except Exception as e:
            logger.error(f"Zone Transfer Lifecycle: Failed to register signal handler: {e}", exc_info=True)
            print(f"Zone Transfer ERROR: Failed to register signal: {e}", file=sys.stderr)

        # Auto-start zone transfer server if enabled on Django startup
        try:
            from constance import config
            logger.info(f"Zone Transfer Lifecycle: Checking ZONE_TRANSFER_ENABLED... value={config.ZONE_TRANSFER_ENABLED}")
            print(f"Zone Transfer: ZONE_TRANSFER_ENABLED = {config.ZONE_TRANSFER_ENABLED}", file=sys.stderr)

            if config.ZONE_TRANSFER_ENABLED:
                logger.info("Zone Transfer Lifecycle: ZONE_TRANSFER_ENABLED is True, auto-starting server")
                print("Zone Transfer: Auto-starting server (enabled=True)", file=sys.stderr)
                _start_zone_transfer_server()
            else:
                logger.info("Zone Transfer Lifecycle: ZONE_TRANSFER_ENABLED is False, not starting server")
                print("Zone Transfer: Not starting server (enabled=False)", file=sys.stderr)
        except Exception as e:
            # During migrations or initial setup, constance may not be available yet
            logger.warning(f"Zone Transfer Lifecycle: Could not check ZONE_TRANSFER_ENABLED on startup: {e}")
            print(f"Zone Transfer WARNING: Could not check config: {e}", file=sys.stderr)
    constance_config = {
        "SHOW_FORWARD_PANEL": ConstanceConfigItem(
            default="Always",
            help_text="Show A/AAAA Records panel in IP Address detailed view.",
            field_type="show_dns_panel",
        ),
        "SHOW_REVERSE_PANEL": ConstanceConfigItem(
            default="Always",
            help_text="Show PTR Records panel in IP Address detailed view.",
            field_type="show_dns_panel",
        ),
        "DNS_VALIDATION_LEVEL": ConstanceConfigItem(
            default="wire-format",
            help_text="DNS validation level for zones and records.",
            field_type="dns_validation_level",
        ),
        "CNAME_RESTRICTION_ENABLED": ConstanceConfigItem(
            default=False,
            help_text="Enforce CNAME exclusivity",
            field_type=bool,
        ),
        "ZONE_TRANSFER_ENABLED": ConstanceConfigItem(
            default=False,
            help_text="Enable DNS zone transfer (AXFR) service. When enabled, the zone transfer server starts automatically.",
            field_type=bool,
        ),
        "ZONE_TRANSFER_PORT": ConstanceConfigItem(
            default=5354,
            help_text="Port for zone transfer server to listen on (default: 5354, non-privileged DNS port).",
            field_type=int,
        ),
        "ZONE_TRANSFER_BIND_ADDRESS": ConstanceConfigItem(
            default="0.0.0.0",
            help_text="IP address for zone transfer server to bind to (default: 0.0.0.0 for all interfaces).",
            field_type=str,
        ),
        "ZONE_TRANSFER_RATE_LIMIT_PER_IP": ConstanceConfigItem(
            default=10,
            help_text="Maximum number of zone transfer requests allowed per IP address within the rate limit window.",
            field_type=int,
        ),
        "ZONE_TRANSFER_RATE_LIMIT_WINDOW": ConstanceConfigItem(
            default=60,
            help_text="Time window in seconds for rate limiting (default: 60 seconds).",
            field_type=int,
        ),
        "ZONE_TRANSFER_MAX_CONN_PER_IP": ConstanceConfigItem(
            default=3,
            help_text="Maximum concurrent zone transfer connections allowed per IP address.",
            field_type=int,
        ),
        "ZONE_TRANSFER_MAX_CONN_GLOBAL": ConstanceConfigItem(
            default=100,
            help_text="Maximum total concurrent zone transfer connections allowed globally.",
            field_type=int,
        ),
        "ZONE_TRANSFER_CONN_TIMEOUT": ConstanceConfigItem(
            default=10,
            help_text="TCP connection timeout in seconds (time to establish connection).",
            field_type=int,
        ),
        "ZONE_TRANSFER_IDLE_TIMEOUT": ConstanceConfigItem(
            default=30,
            help_text="Idle connection timeout in seconds (time before closing inactive connections).",
            field_type=int,
        ),
        "ZONE_TRANSFER_OPERATION_TIMEOUT": ConstanceConfigItem(
            default=30,
            help_text="Operation timeout in seconds for TSIG validation and zone rendering.",
            field_type=int,
        ),
        "ZONE_TRANSFER_DB_TIMEOUT": ConstanceConfigItem(
            default=10,
            help_text="Database query timeout in seconds for zone transfer operations.",
            field_type=int,
        ),
        "ZONE_TRANSFER_NORMALIZE_TIMING": ConstanceConfigItem(
            default=False,
            help_text="Enable response time normalization to prevent timing attacks. Adds 50-60ms latency to all responses.",
            field_type=bool,
        ),
        "ZONE_TRANSFER_MIN_RESPONSE_TIME_MS": ConstanceConfigItem(
            default=50,
            help_text="Minimum response time in milliseconds for timing normalization (prevents timing-based key enumeration).",
            field_type=int,
        ),
        "ZONE_TRANSFER_TIMING_JITTER_MS": ConstanceConfigItem(
            default=10,
            help_text="Random jitter in milliseconds added to response times (prevents statistical timing analysis).",
            field_type=int,
        ),
        "ZONE_TRANSFER_CONSTANT_TIME_VALIDATION": ConstanceConfigItem(
            default=True,
            help_text="Always compute HMAC for TSIG validation even when key doesn't exist (prevents timing-based key enumeration). Adds ~10-20ms to BADKEY errors.",
            field_type=bool,
        ),
    }


config = NautobotDnsModelsConfig  # pylint:disable=invalid-name
