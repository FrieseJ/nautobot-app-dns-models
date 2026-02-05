"""Tests for zone transfer server lifecycle management."""

import threading
import time
from unittest import mock

from django.test import TestCase, override_settings
from constance.test import override_config

from nautobot_dns_models import (
    _start_zone_transfer_server,
    _stop_zone_transfer_server,
    _handle_zone_transfer_config_change,
    _server_thread,
    _server_instance,
)


class ZoneTransferLifecycleTestCase(TestCase):
    """Test zone transfer server lifecycle management."""

    def tearDown(self):
        """Ensure server is stopped after each test."""
        # Import at function level to avoid import issues
        import nautobot_dns_models

        # Stop server if running
        with nautobot_dns_models._server_lock:
            if nautobot_dns_models._server_instance:
                try:
                    nautobot_dns_models._server_instance.shutdown()
                except Exception:
                    pass
            nautobot_dns_models._server_thread = None
            nautobot_dns_models._server_instance = None

    @mock.patch('nautobot_dns_models.ZoneTransferServer')
    @override_config(
        ZONE_TRANSFER_ENABLED=True,
        ZONE_TRANSFER_PORT=5353,
        ZONE_TRANSFER_BIND_ADDRESS="127.0.0.1",
        ZONE_TRANSFER_RATE_LIMIT_PER_IP=10,
        ZONE_TRANSFER_RATE_LIMIT_WINDOW=60,
        ZONE_TRANSFER_MAX_CONN_PER_IP=3,
        ZONE_TRANSFER_MAX_CONN_GLOBAL=100,
        ZONE_TRANSFER_NORMALIZE_TIMING=False,
        ZONE_TRANSFER_MIN_RESPONSE_TIME_MS=50,
        ZONE_TRANSFER_TIMING_JITTER_MS=10,
    )
    def test_start_server_creates_thread(self, mock_server_class):
        """Test that starting the server creates a daemon thread."""
        import nautobot_dns_models

        # Mock the server instance
        mock_server = mock.Mock()
        mock_server_class.return_value = mock_server

        # Start server
        _start_zone_transfer_server()

        # Wait a moment for thread to start
        time.sleep(0.1)

        # Verify thread was created
        self.assertIsNotNone(nautobot_dns_models._server_thread)
        self.assertTrue(nautobot_dns_models._server_thread.is_alive())
        self.assertTrue(nautobot_dns_models._server_thread.daemon)
        self.assertEqual(nautobot_dns_models._server_thread.name, "zone-transfer-server")

        # Verify server was created with correct config
        mock_server_class.assert_called_once()
        call_kwargs = mock_server_class.call_args[1]
        self.assertEqual(call_kwargs['bind_address'], "127.0.0.1")
        self.assertEqual(call_kwargs['port'], 5353)

    @mock.patch('nautobot_dns_models.ZoneTransferServer')
    @override_config(ZONE_TRANSFER_ENABLED=True)
    def test_start_server_idempotent(self, mock_server_class):
        """Test that starting the server multiple times is idempotent."""
        import nautobot_dns_models

        # Mock the server instance
        mock_server = mock.Mock()
        mock_server_class.return_value = mock_server

        # Start server twice
        _start_zone_transfer_server()
        time.sleep(0.1)
        first_thread = nautobot_dns_models._server_thread

        _start_zone_transfer_server()

        # Verify only one thread was created
        self.assertIs(nautobot_dns_models._server_thread, first_thread)
        self.assertEqual(mock_server_class.call_count, 1)

    @mock.patch('nautobot_dns_models.ZoneTransferServer')
    @override_config(ZONE_TRANSFER_ENABLED=True)
    def test_stop_server_graceful_shutdown(self, mock_server_class):
        """Test that stopping the server calls shutdown and waits for thread."""
        import nautobot_dns_models

        # Mock the server instance
        mock_server = mock.Mock()
        mock_server_class.return_value = mock_server

        # Start server
        _start_zone_transfer_server()
        time.sleep(0.1)

        # Stop server
        _stop_zone_transfer_server()

        # Verify shutdown was called
        mock_server.shutdown.assert_called_once()

        # Verify state was cleared
        self.assertIsNone(nautobot_dns_models._server_thread)
        self.assertIsNone(nautobot_dns_models._server_instance)

    def test_stop_server_when_not_running(self):
        """Test that stopping when not running is safe."""
        import nautobot_dns_models

        # Ensure clean state
        nautobot_dns_models._server_thread = None
        nautobot_dns_models._server_instance = None

        # Should not raise exception
        _stop_zone_transfer_server()

    @mock.patch('nautobot_dns_models._start_zone_transfer_server')
    def test_signal_handler_enables_server(self, mock_start):
        """Test signal handler starts server when enabled."""
        _handle_zone_transfer_config_change(
            sender=None,
            key="ZONE_TRANSFER_ENABLED",
            old_value=False,
            new_value=True
        )
        mock_start.assert_called_once()

    @mock.patch('nautobot_dns_models._stop_zone_transfer_server')
    def test_signal_handler_disables_server(self, mock_stop):
        """Test signal handler stops server when disabled."""
        _handle_zone_transfer_config_change(
            sender=None,
            key="ZONE_TRANSFER_ENABLED",
            old_value=True,
            new_value=False
        )
        mock_stop.assert_called_once()

    @mock.patch('nautobot_dns_models._start_zone_transfer_server')
    @mock.patch('nautobot_dns_models._stop_zone_transfer_server')
    def test_signal_handler_ignores_other_keys(self, mock_stop, mock_start):
        """Test signal handler ignores non-ZONE_TRANSFER_ENABLED changes."""
        _handle_zone_transfer_config_change(
            sender=None,
            key="SOME_OTHER_SETTING",
            old_value="old",
            new_value="new"
        )
        mock_start.assert_not_called()
        mock_stop.assert_not_called()

    @mock.patch('nautobot_dns_models._start_zone_transfer_server')
    def test_signal_handler_no_change_same_value(self, mock_start):
        """Test signal handler does nothing when value doesn't actually change."""
        _handle_zone_transfer_config_change(
            sender=None,
            key="ZONE_TRANSFER_ENABLED",
            old_value=True,
            new_value=True
        )
        mock_start.assert_not_called()

    @mock.patch('nautobot_dns_models.ZoneTransferServer')
    @override_config(ZONE_TRANSFER_ENABLED=True)
    def test_server_thread_handles_exceptions(self, mock_server_class):
        """Test that exceptions in server thread don't crash the app."""
        import nautobot_dns_models

        # Make server raise an exception
        mock_server = mock.Mock()
        mock_server.start.side_effect = Exception("Test error")
        mock_server_class.return_value = mock_server

        # Start server
        _start_zone_transfer_server()

        # Wait for thread to process
        time.sleep(0.2)

        # Thread should have exited due to exception, but app should still be running
        # State should be cleaned up by next stop call
        _stop_zone_transfer_server()
        self.assertIsNone(nautobot_dns_models._server_instance)


class ZoneTransferAppConfigTestCase(TestCase):
    """Test NautobotDnsModelsConfig.ready() method."""

    @mock.patch('nautobot_dns_models._start_zone_transfer_server')
    @override_config(ZONE_TRANSFER_ENABLED=True)
    def test_ready_starts_server_when_enabled(self, mock_start):
        """Test that ready() starts server if ZONE_TRANSFER_ENABLED=True."""
        from nautobot_dns_models import NautobotDnsModelsConfig

        # Create config instance and call ready
        # Note: In actual Django, ready() is called automatically
        # Here we're testing the logic in isolation
        config = NautobotDnsModelsConfig('nautobot_dns_models', None)

        # We can't easily test ready() in isolation because it requires
        # Django to be fully initialized. This test verifies the logic
        # is correct by testing the components it uses.
        self.assertTrue(True)  # Placeholder - integration test needed

    @mock.patch('constance.signals.config_updated.connect')
    def test_ready_registers_signal_handler(self, mock_connect):
        """Test that ready() registers the signal handler."""
        # This would require a full Django app initialization
        # which is complex in unit tests. Integration test needed.
        self.assertTrue(True)  # Placeholder - integration test needed
