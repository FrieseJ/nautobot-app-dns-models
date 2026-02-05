# NTC-Compliant Service Lifecycle Pattern for Nautobot Apps

## Overview

This document provides comprehensive guidance on implementing background services in Nautobot apps following Network to Code (NTC) best practices and approved patterns.

## Table of Contents

1. [Key Principles](#key-principles)
2. [Why Management Commands Are Rejected](#why-management-commands-are-rejected)
3. [AppConfig.ready() Best Practices](#appconfigready-best-practices)
4. [Constance Signal Handler Pattern](#constance-signal-handler-pattern)
5. [Thread vs Process Considerations](#thread-vs-process-considerations)
6. [Recommended Approaches](#recommended-approaches)
7. [Code Examples](#code-examples)
8. [Testing Strategies](#testing-strategies)
9. [References](#references)

---

## Key Principles

### Nautobot's Architecture Philosophy

Nautobot is built on Django and follows Django's application lifecycle model. Key architectural principles:

1. **Separation of Concerns**: Web services, background workers, and auxiliary services should be separate processes
2. **Django Lifecycle Compliance**: Apps must work within Django's initialization and request/response cycle
3. **Jobs Framework**: Background work should use Nautobot's Jobs framework with Celery workers
4. **No Persistent Daemons in Apps**: Apps should not start long-running daemon threads or processes

### What Nautobot DOES Support

✅ **Nautobot Jobs**: Asynchronous tasks executed by Celery workers
✅ **Signal Handlers**: One-time setup code during app initialization
✅ **Database-Backed Configuration**: Dynamic settings via Constance
✅ **Webhooks**: Event-driven integrations
✅ **API Extensions**: Custom REST/GraphQL endpoints

### What Nautobot DOES NOT Support

❌ **Persistent daemon threads** within apps
❌ **Management commands** as primary service mechanisms
❌ **Direct asyncio event loops** in the web application context
❌ **Network listeners** (TCP/UDP servers) embedded in apps

---

## Why Management Commands Are Rejected

### The Problem with Management Commands

Management commands (e.g., `nautobot-server myapp_start_service`) were a common pattern in older Django applications, but NTC rejects this approach for several reasons:

#### 1. **Process Management Complexity**

Management commands require external process managers (systemd, supervisor, Docker) to:
- Start the service on system boot
- Monitor and restart on failure
- Manage logs and output
- Handle graceful shutdown

This adds operational complexity and deployment dependencies.

#### 2. **No Integration with Nautobot's Infrastructure**

Management commands run outside Nautobot's service ecosystem:
- No visibility in Nautobot's admin interface
- No integration with Nautobot's logging system
- No access to Celery worker monitoring
- Separate health check mechanisms required

#### 3. **Configuration Synchronization Issues**

Management commands must:
- Re-read database configuration on changes
- Implement their own configuration reload logic
- Handle database connection pooling separately
- Manage migrations and schema changes independently

#### 4. **Testing Challenges**

Management commands are difficult to test:
- Require separate test harnesses
- Cannot use Nautobot's test utilities
- Integration testing becomes complex
- CI/CD pipelines need custom service management

#### 5. **Deployment Inconsistencies**

Different deployment platforms handle management commands differently:
- Docker: Requires multi-process containers or sidecars
- Kubernetes: Needs separate Deployment/Pod definitions
- Traditional VMs: Requires systemd unit files
- Cloud PaaS: May not support background processes

### NTC's Position

From NTC's perspective, if a feature requires a management command to function, it should either:

1. **Use the Jobs Framework**: Schedule as a Job that Celery workers execute
2. **Be an External Service**: Deploy as a separate microservice with API integration
3. **Use Webhooks**: Trigger external systems via Nautobot's webhook mechanism

---

## AppConfig.ready() Best Practices

### What is `ready()`?

The `ready()` method is called once during Django app initialization after all models are loaded. It's part of Django's `AppConfig` class and `NautobotAppConfig` extends this functionality.

### Official Documentation

From [Nautobot App Development Documentation](https://archive.docs.nautobot.com/projects/core/en/v2.0.0-alpha.2/plugins/development/):

```python
from nautobot.apps import NautobotAppConfig

class MyAppConfig(NautobotAppConfig):
    name = "nautobot_myapp"
    verbose_name = "My App"
    version = "1.0.0"

    def ready(self):
        super().ready()
        # App initialization code here
```

### Approved Uses of `ready()`

✅ **Importing signal handlers**:
```python
def ready(self):
    super().ready()
    from . import signals  # noqa: F401
```

✅ **Registering signal connections**:
```python
def ready(self):
    super().ready()
    from nautobot.apps import nautobot_database_ready
    from .signals import initialize_custom_fields

    nautobot_database_ready.connect(
        initialize_custom_fields,
        sender=self
    )
```

✅ **One-time configuration setup**:
```python
def ready(self):
    super().ready()
    from .config import validate_app_settings
    validate_app_settings(self.constance_config)
```

### WRONG Uses of `ready()` (Anti-Patterns)

❌ **Starting daemon threads**:
```python
# DON'T DO THIS!
def ready(self):
    super().ready()
    import threading
    thread = threading.Thread(target=self.run_service, daemon=True)
    thread.start()
```

**Why it's wrong:**
- `ready()` is called during Django initialization, which happens in multiple contexts:
  - During migrations (`nautobot-server migrate`)
  - During testing
  - During management command execution
  - In each Gunicorn worker process
- Starting a thread in each worker process creates multiple conflicting instances
- No graceful shutdown mechanism
- No health monitoring or restart capability

❌ **Starting asyncio event loops**:
```python
# DON'T DO THIS!
def ready(self):
    super().ready()
    import asyncio
    loop = asyncio.new_event_loop()
    loop.run_until_complete(self.start_server())
```

**Why it's wrong:**
- Blocks the initialization process
- Conflicts with existing event loops in async contexts
- Cannot run alongside Django's WSGI application
- No way to stop or manage the loop

❌ **Database operations without signal protection**:
```python
# DON'T DO THIS!
def ready(self):
    super().ready()
    from .models import MyModel
    MyModel.objects.create(name="default")  # May run during migrations!
```

**Why it's wrong:**
- May execute before migrations complete
- Runs in test environments unintentionally
- No idempotency guarantees

### Best Practices Summary

| Pattern | Allowed in `ready()`? | Notes |
|---------|----------------------|-------|
| Import signal handlers | ✅ Yes | Standard pattern |
| Register signals | ✅ Yes | Use `nautobot_database_ready` for DB operations |
| Validate configuration | ✅ Yes | Read-only checks |
| Start daemon threads | ❌ No | Use Jobs framework instead |
| Start network listeners | ❌ No | Use external services |
| Database writes | ⚠️ Only via signals | Use `nautobot_database_ready` |
| Blocking operations | ❌ No | Delays application startup |

---

## Constance Signal Handler Pattern

### What is `nautobot_database_ready`?

`nautobot_database_ready` is a custom Nautobot signal that fires after the database is confirmed ready. It's triggered during:

- `nautobot-server migrate` (after all migrations complete)
- `nautobot-server post_upgrade` (after upgrade operations)

**Important**: This signal does **NOT** fire during normal server operation. It's for one-time initialization tasks.

### When to Use This Signal

Use `nautobot_database_ready` for:

✅ Creating default `CustomFields`
✅ Ensuring `Relationships` exist
✅ Populating reference data
✅ Validating database schema
✅ Initializing constance-backed configuration

### Example: Initializing Custom Fields

```python
# signals.py
from nautobot.extras.models import CustomField
from django.contrib.contenttypes.models import ContentType

def create_default_custom_fields(sender, **kwargs):
    """Create default custom fields for this app."""
    zone_content_type = ContentType.objects.get_for_model(
        sender.get_model("DNSZone")
    )

    CustomField.objects.get_or_create(
        key="external_zone_id",
        defaults={
            "label": "External Zone ID",
            "type": "text",
            "description": "External DNS provider zone identifier"
        }
    )

# __init__.py
from nautobot.apps import nautobot_database_ready, NautobotAppConfig

class MyAppConfig(NautobotAppConfig):
    # ... config attributes ...

    def ready(self):
        super().ready()
        from .signals import create_default_custom_fields
        nautobot_database_ready.connect(
            create_default_custom_fields,
            sender=self
        )
```

### Example: Ensuring Relationships Exist

```python
# signals.py
from nautobot.extras.models import Relationship, RelationshipAssociation
from django.contrib.contenttypes.models import ContentType

def ensure_zone_relationships(sender, **kwargs):
    """Ensure required relationships exist."""
    zone_ct = ContentType.objects.get_for_model(sender.get_model("DNSZone"))
    device_ct = ContentType.objects.get(app_label="dcim", model="device")

    Relationship.objects.get_or_create(
        key="zone_authoritative_devices",
        defaults={
            "label": "Authoritative Devices",
            "type": "many-to-many",
            "source_type": zone_ct,
            "destination_type": device_ct,
        }
    )
```

### Why NOT Use This for Background Services

The `nautobot_database_ready` signal is **NOT suitable for starting background services** because:

1. It fires during migrations and upgrades, not during server startup
2. It may fire multiple times (once per migration run)
3. It provides no lifecycle management for started services
4. There's no corresponding "shutdown" signal

---

## Thread vs Process Considerations

### Understanding Django's Deployment Model

Nautobot typically runs as a WSGI application with multiple worker processes:

```
┌─────────────────────────────────────────────────┐
│  Gunicorn Master Process                        │
│  ┌───────────────────────────────────────────┐  │
│  │  Worker Process 1                         │  │
│  │  ├─ Nautobot Django App                   │  │
│  │  └─ ready() called here                   │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │  Worker Process 2                         │  │
│  │  ├─ Nautobot Django App                   │  │
│  │  └─ ready() called here too!              │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │  Worker Process 3                         │  │
│  │  └─ ready() called here as well!          │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

### The Multi-Process Problem

If you start a background thread in `ready()`, you'll start **N threads across N worker processes**:

```python
# This is WRONG and will create multiple instances!
def ready(self):
    super().ready()
    thread = threading.Thread(target=background_service, daemon=True)
    thread.start()  # Creates thread in EVERY worker process!
```

**Result**:
- 4 Gunicorn workers = 4 separate background service instances
- Each instance tries to bind to the same port → **conflict**
- Each instance processes the same work → **duplication**
- No coordination between instances → **race conditions**

### Why Processes Are Better for Services

Background services should be **separate processes** because:

1. **Isolation**: Service failures don't crash web workers
2. **Resource Control**: Separate CPU/memory limits
3. **Independent Scaling**: Scale web and service tiers independently
4. **Clean Shutdown**: Can be stopped without affecting web requests
5. **Monitoring**: Separate health checks and logs

### Nautobot's Solution: Celery Workers

Nautobot solves this with Celery:

```
┌───────────────────┐      ┌──────────────┐      ┌─────────────────┐
│  Gunicorn Workers │      │    Redis     │      │  Celery Workers │
│  (Web Requests)   │─────►│   (Broker)   │◄─────│  (Background)   │
│  - UI rendering   │      │              │      │  - Jobs         │
│  - API endpoints  │      │              │      │  - Webhooks     │
│  - Enqueue Jobs   │      │              │      │  - Git sync     │
└───────────────────┘      └──────────────┘      └─────────────────┘
```

**Benefits:**
- Jobs are enqueued from web workers, executed in Celery workers
- Celery workers are separate processes with independent lifecycle
- Built-in retry logic, error handling, and monitoring
- Status visible in Nautobot UI at `/worker-status/`

---

## Recommended Approaches

### Approach 1: Nautobot Job (Long-Running)

**Use When**: You need a persistent service that can be managed through Nautobot's UI.

**Architecture**:
```python
# jobs.py
from nautobot.apps.jobs import Job, register_jobs
import asyncio
from constance import config

class BackgroundServiceJob(Job):
    """Long-running background service job."""

    class Meta:
        name = "Background Service"
        description = "Runs the background service continuously"
        enabled = True
        soft_time_limit = 86400  # 24 hours
        task_queues = ["services"]  # Dedicated queue

    def run(self):
        """Execute the background service."""
        # Check if enabled via constance
        if not config.SERVICE_ENABLED:
            self.logger.info("Service disabled via configuration")
            return

        self.logger.info("Starting background service")

        # Run async service
        asyncio.run(self._run_async_service())

    async def _run_async_service(self):
        """Run the actual service logic."""
        # Your service implementation here
        pass

register_jobs(BackgroundServiceJob)
```

**Pros:**
- ✅ Uses NTC-approved Jobs framework
- ✅ Visible in Nautobot UI
- ✅ Can be stopped/started from UI
- ✅ Built-in logging and monitoring
- ✅ Leverages existing Celery infrastructure

**Cons:**
- ⚠️ Jobs have time limits (configurable)
- ⚠️ Requires manual scheduling or auto-restart
- ⚠️ May not be intended use case for Jobs

**Deployment**:
```bash
# Start dedicated Celery worker for services
nautobot-server celery worker -q services --loglevel info
```

**Configuration**:
```python
# In NautobotAppConfig
constance_config = {
    "SERVICE_ENABLED": ConstanceConfigItem(
        default=False,
        help_text="Enable background service",
        field_type=bool,
    ),
}
```

### Approach 2: External Service (Sidecar)

**Use When**: You need a truly independent service with no lifecycle constraints.

**Architecture**:
```
┌─────────────────┐      REST API      ┌──────────────────────┐
│  Nautobot Web   │◄──────────────────►│  External Service    │
│  - Admin UI     │                    │  - Standalone Python │
│  - Configuration│                    │  - Reads config      │
│  - Status API   │                    │    via API           │
└─────────────────┘                    └──────────────────────┘
```

**Implementation**:

1. **Standalone Service Script** (`service/server.py`):
```python
#!/usr/bin/env python
"""Standalone background service."""
import os
import sys
import time
import requests
import asyncio
import signal

NAUTOBOT_URL = os.environ.get("NAUTOBOT_URL", "http://localhost:8000")
NAUTOBOT_TOKEN = os.environ.get("NAUTOBOT_TOKEN")

class BackgroundService:
    def __init__(self):
        self.running = False
        self.config = {}

    def load_config(self):
        """Load configuration from Nautobot API."""
        response = requests.get(
            f"{NAUTOBOT_URL}/api/plugins/myapp/config/",
            headers={"Authorization": f"Token {NAUTOBOT_TOKEN}"}
        )
        self.config = response.json()

    async def run(self):
        """Main service loop."""
        self.running = True

        while self.running:
            self.load_config()

            if not self.config.get("enabled"):
                await asyncio.sleep(10)
                continue

            # Service logic here
            await asyncio.sleep(1)

    def shutdown(self, signum, frame):
        """Handle shutdown signal."""
        print("Shutting down...")
        self.running = False

if __name__ == "__main__":
    service = BackgroundService()

    # Register signal handlers
    signal.signal(signal.SIGTERM, service.shutdown)
    signal.signal(signal.SIGINT, service.shutdown)

    # Run service
    asyncio.run(service.run())
```

2. **Systemd Unit File** (`systemd/myapp-service.service`):
```ini
[Unit]
Description=My App Background Service
After=network.target nautobot.service
Requires=nautobot.service

[Service]
Type=simple
User=nautobot
Group=nautobot
WorkingDirectory=/opt/nautobot
Environment="NAUTOBOT_URL=http://localhost:8000"
Environment="NAUTOBOT_TOKEN={{ nautobot_token }}"
ExecStart=/opt/nautobot/venv/bin/python /opt/nautobot/service/server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

3. **Nautobot API Endpoint** (for configuration):
```python
# api/views.py
from rest_framework.decorators import api_view
from rest_framework.response import Response
from constance import config

@api_view(["GET"])
def service_config(request):
    """Return service configuration."""
    return Response({
        "enabled": config.SERVICE_ENABLED,
        "port": config.SERVICE_PORT,
        "bind_address": config.SERVICE_BIND_ADDRESS,
    })
```

**Pros:**
- ✅ Complete isolation from Nautobot
- ✅ Independent lifecycle
- ✅ Can bind to privileged ports
- ✅ Standard systemd management
- ✅ Clean separation of concerns

**Cons:**
- ⚠️ Separate deployment package
- ⚠️ Additional infrastructure
- ⚠️ More complex monitoring

### Approach 3: Webhook-Triggered (Event-Driven)

**Use When**: Service can be event-driven rather than continuously running.

**Architecture**:
```
┌─────────────┐   Webhook    ┌──────────────┐   NOTIFY   ┌─────────────┐
│ Zone Change │─────────────►│ Nautobot Job │───────────►│ External    │
│ in Nautobot │              │ Send NOTIFY  │            │ DNS Server  │
└─────────────┘              └──────────────┘            └─────────────┘
                                                                │
                                                          AXFR Request
                                                                │
                                                                ▼
                                                    ┌────────────────────┐
                                                    │  Zone Transfer     │
                                                    │  Service (minimal) │
                                                    └────────────────────┘
```

**Implementation**:
```python
# jobs.py
from nautobot.apps.jobs import Job, register_jobs
import dns.query
import dns.message

class SendNotifyJob(Job):
    """Send DNS NOTIFY to secondary servers."""

    class Meta:
        name = "Send DNS NOTIFY"
        description = "Notify secondary servers of zone changes"

    def run(self, zone_id):
        """Send NOTIFY for a zone."""
        from .models import DNSZone

        zone = DNSZone.objects.get(id=zone_id)

        for acl in zone.transfer_acls.all():
            self.logger.info(f"Sending NOTIFY to {acl.ip_address}")

            # Build NOTIFY message
            notify = dns.message.make_query(
                zone.name,
                "SOA",
                "IN"
            )
            notify.set_opcode(dns.opcode.NOTIFY)

            # Send NOTIFY
            try:
                dns.query.udp(notify, str(acl.ip_address), timeout=5)
                self.logger.info(f"NOTIFY sent to {acl.ip_address}")
            except Exception as e:
                self.logger.error(f"Failed to send NOTIFY: {e}")

register_jobs(SendNotifyJob)
```

**Webhook Configuration** (in Nautobot UI):
- **Object Type**: DNS Zone
- **Events**: Create, Update
- **URL**: `http://localhost:8000/api/plugins/dns/jobs/send-notify/`
- **HTTP Method**: POST

**Pros:**
- ✅ Event-driven, no continuous process
- ✅ Uses standard webhooks
- ✅ Minimal resource usage
- ✅ Standard DNS workflow

**Cons:**
- ⚠️ Requires external zone transfer service
- ⚠️ Push model (not always suitable)
- ⚠️ May miss events if webhook fails

---

## Code Examples

### Complete AppConfig Example

```python
# __init__.py
from importlib import metadata
from nautobot.apps import NautobotAppConfig, ConstanceConfigItem

__version__ = metadata.version(__name__)

class MyAppConfig(NautobotAppConfig):
    """App configuration."""

    name = "nautobot_myapp"
    verbose_name = "My App"
    version = __version__
    author = "Your Organization"
    description = "My Nautobot App"
    base_url = "myapp"

    # Database-backed configuration
    constance_config = {
        "SERVICE_ENABLED": ConstanceConfigItem(
            default=False,
            help_text="Enable background service",
            field_type=bool,
        ),
        "SERVICE_PORT": ConstanceConfigItem(
            default=5353,
            help_text="Service port",
            field_type=int,
        ),
    }

    def ready(self):
        """Initialize app after Django loads."""
        super().ready()

        # Import signal handlers
        from . import signals  # noqa: F401

        # Register signal connections
        from nautobot.apps import nautobot_database_ready
        from .signals import initialize_app

        nautobot_database_ready.connect(
            initialize_app,
            sender=self
        )

config = MyAppConfig
```

### Signal Handler with Idempotency

```python
# signals.py
from nautobot.extras.models import CustomField
from django.contrib.contenttypes.models import ContentType
import logging

logger = logging.getLogger(__name__)

def initialize_app(sender, **kwargs):
    """Initialize app resources (idempotent)."""
    try:
        _create_custom_fields(sender)
        _create_relationships(sender)
        logger.info("App initialization complete")
    except Exception as e:
        logger.error(f"App initialization failed: {e}")

def _create_custom_fields(sender):
    """Create custom fields (idempotent)."""
    zone_ct = ContentType.objects.get_for_model(
        sender.get_model("DNSZone")
    )

    field, created = CustomField.objects.get_or_create(
        key="external_id",
        defaults={
            "label": "External ID",
            "type": "text",
            "description": "External system identifier"
        }
    )

    if created:
        field.content_types.add(zone_ct)
        logger.info("Created custom field: external_id")

def _create_relationships(sender):
    """Create relationships (idempotent)."""
    # Similar pattern...
    pass
```

### Job with Configuration Monitoring

```python
# jobs.py
from nautobot.apps.jobs import Job, register_jobs
from constance import config
import asyncio
import logging

logger = logging.getLogger(__name__)

class ConfigMonitoringServiceJob(Job):
    """Service that monitors configuration changes."""

    class Meta:
        name = "Configuration Monitoring Service"
        description = "Monitors and reacts to configuration changes"
        enabled = True
        soft_time_limit = 86400
        task_queues = ["services"]

    def run(self):
        """Run the service."""
        self.logger.info("Starting configuration monitoring service")
        asyncio.run(self._monitor())

    async def _monitor(self):
        """Monitor configuration and restart service on changes."""
        last_config = self._get_config()
        service_task = None

        while True:
            current_config = self._get_config()

            # Check if config changed
            if current_config != last_config:
                self.logger.info("Configuration changed, restarting service")

                # Stop old service
                if service_task:
                    service_task.cancel()
                    try:
                        await service_task
                    except asyncio.CancelledError:
                        pass

                # Start new service with new config
                if current_config["enabled"]:
                    service_task = asyncio.create_task(
                        self._run_service(current_config)
                    )

                last_config = current_config

            await asyncio.sleep(10)  # Check every 10 seconds

    def _get_config(self):
        """Get current configuration."""
        return {
            "enabled": config.SERVICE_ENABLED,
            "port": config.SERVICE_PORT,
            "bind_address": config.SERVICE_BIND_ADDRESS,
        }

    async def _run_service(self, config):
        """Run the actual service."""
        self.logger.info(f"Starting service on {config['bind_address']}:{config['port']}")

        # Your service implementation here
        try:
            while True:
                # Service logic
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            self.logger.info("Service stopped")
            raise

register_jobs(ConfigMonitoringServiceJob)
```

### Graceful Shutdown Handler

```python
# service/shutdown.py
import signal
import asyncio
import logging

logger = logging.getLogger(__name__)

class GracefulShutdown:
    """Handle graceful shutdown of async services."""

    def __init__(self):
        self.shutdown_event = asyncio.Event()
        self.tasks = []

    def register_signals(self):
        """Register signal handlers."""
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum, frame):
        """Handle shutdown signal."""
        logger.info(f"Received signal {signum}, initiating shutdown")
        self.shutdown_event.set()

    def add_task(self, task):
        """Add a task to be cancelled on shutdown."""
        self.tasks.append(task)

    async def wait(self):
        """Wait for shutdown signal."""
        await self.shutdown_event.wait()

    async def cleanup(self):
        """Cancel all registered tasks."""
        logger.info(f"Cancelling {len(self.tasks)} tasks")

        for task in self.tasks:
            task.cancel()

        # Wait for tasks to complete
        results = await asyncio.gather(*self.tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, Exception) and not isinstance(result, asyncio.CancelledError):
                logger.error(f"Task {i} failed during shutdown: {result}")

        logger.info("Cleanup complete")

# Usage:
async def main():
    shutdown = GracefulShutdown()
    shutdown.register_signals()

    # Start services
    service_task = asyncio.create_task(run_service())
    shutdown.add_task(service_task)

    # Wait for shutdown
    await shutdown.wait()
    await shutdown.cleanup()
```

---

## Testing Strategies

### Testing AppConfig.ready()

```python
# tests/test_config.py
from django.test import TestCase
from nautobot_myapp import MyAppConfig

class TestAppConfig(TestCase):
    """Test app configuration."""

    def test_ready_is_idempotent(self):
        """Test that ready() can be called multiple times."""
        config = MyAppConfig("nautobot_myapp", "")

        # Call ready multiple times
        config.ready()
        config.ready()
        config.ready()

        # Should not raise exceptions or create duplicates

    def test_signals_registered(self):
        """Test that signals are properly registered."""
        from django.db.models import signals
        from nautobot.apps import nautobot_database_ready

        # Check signal receivers
        receivers = nautobot_database_ready.receivers

        # Find our receiver
        found = any(
            "myapp" in str(receiver)
            for receiver in receivers
        )

        self.assertTrue(found, "Signal handler not registered")
```

### Testing Signal Handlers

```python
# tests/test_signals.py
from django.test import TestCase
from nautobot.extras.models import CustomField
from nautobot_myapp.signals import initialize_app
from nautobot_myapp import MyAppConfig

class TestSignalHandlers(TestCase):
    """Test signal handlers."""

    def test_initialize_app_creates_custom_fields(self):
        """Test that custom fields are created."""
        # Delete existing fields
        CustomField.objects.filter(key="external_id").delete()

        # Run signal handler
        config = MyAppConfig("nautobot_myapp", "")
        initialize_app(sender=config)

        # Check field was created
        field = CustomField.objects.get(key="external_id")
        self.assertEqual(field.label, "External ID")

    def test_initialize_app_is_idempotent(self):
        """Test that signal handler can run multiple times."""
        config = MyAppConfig("nautobot_myapp", "")

        # Run multiple times
        initialize_app(sender=config)
        count1 = CustomField.objects.filter(key="external_id").count()

        initialize_app(sender=config)
        count2 = CustomField.objects.filter(key="external_id").count()

        # Should not create duplicates
        self.assertEqual(count1, count2)
```

### Testing Jobs

```python
# tests/test_jobs.py
from django.test import TestCase
from nautobot_myapp.jobs import ConfigMonitoringServiceJob
from constance.test import override_config

class TestJobs(TestCase):
    """Test job implementations."""

    @override_config(SERVICE_ENABLED=True, SERVICE_PORT=5353)
    def test_job_reads_configuration(self):
        """Test that job reads configuration."""
        job = ConfigMonitoringServiceJob()

        config = job._get_config()

        self.assertTrue(config["enabled"])
        self.assertEqual(config["port"], 5353)

    @override_config(SERVICE_ENABLED=False)
    def test_job_respects_disabled_config(self):
        """Test that job doesn't run when disabled."""
        job = ConfigMonitoringServiceJob()

        # Run job (should exit early)
        result = job.run()

        # Check that service didn't start
        # (implementation-specific assertions)
```

### Integration Testing

```python
# tests/test_integration.py
from django.test import TestCase, override_settings
from constance.test import override_config
from nautobot_myapp import MyAppConfig

class TestIntegration(TestCase):
    """Integration tests."""

    def test_full_initialization_flow(self):
        """Test complete initialization flow."""
        # Initialize app
        config = MyAppConfig("nautobot_myapp", "")
        config.ready()

        # Trigger database ready signal
        from nautobot.apps import nautobot_database_ready
        nautobot_database_ready.send(sender=config, apps=None)

        # Verify initialization completed
        from nautobot.extras.models import CustomField
        self.assertTrue(
            CustomField.objects.filter(key="external_id").exists()
        )

    @override_config(SERVICE_ENABLED=True)
    def test_job_can_be_scheduled(self):
        """Test that job can be scheduled and executed."""
        from nautobot_myapp.jobs import ConfigMonitoringServiceJob
        from nautobot.extras.models import Job, JobResult

        # Get job
        job_model = Job.objects.get(
            module_name="nautobot_myapp.jobs",
            job_class_name="ConfigMonitoringServiceJob"
        )

        # Schedule job
        job_result = JobResult.objects.create(
            name=job_model.name,
            job_model=job_model,
        )

        # Execute job (in test, with timeout)
        # (implementation-specific)
```

---

## References

### Official Nautobot Documentation

- [Developing Apps - Nautobot Documentation](https://archive.docs.nautobot.com/projects/core/en/v2.0.0-alpha.2/plugins/development/)
- [Celery Task Queues - Nautobot Documentation](https://docs.nautobot.com/projects/core/en/stable/user-guide/administration/guides/celery-queues/)
- [Deploying Nautobot Services](https://docs.nautobot.com/projects/core/en/stable/user-guide/administration/installation/services/)
- [Jobs Developer Guide](https://archive.docs.nautobot.com/projects/core/en/v2.1.1/development/jobs/)

### Django Documentation

- [Django Applications - AppConfig](https://docs.djangoproject.com/en/stable/ref/applications/)
- [Django Signals](https://docs.djangoproject.com/en/stable/topics/signals/)

### Related Projects

- [netbox-plugin-bind-provisioner (PyPI)](https://pypi.org/project/netbox-plugin-bind-provisioner/)
- [netbox-plugin-dns (GitHub)](https://github.com/peteeckel/netbox-plugin-dns)
- [Background Jobs | NetBox Documentation](https://netboxlabs.com/docs/netbox/plugins/development/background-jobs/)

### External Resources

- [Django AppConfig Best Practices](https://docs.djangoproject.com/en/stable/ref/applications/#for-application-authors)
- [Celery Documentation](https://docs.celeryproject.org/)
- [Systemd Service Management](https://www.freedesktop.org/software/systemd/man/systemd.service.html)

---

## Summary

### Key Takeaways

1. **No Persistent Daemons in Apps**: Nautobot apps should not start daemon threads or background processes in `ready()`

2. **Use Jobs Framework**: For background work, use Nautobot's Jobs framework with Celery workers

3. **External Services for Persistence**: If you need a persistent service, deploy it as a separate process/container

4. **Signals for Initialization**: Use `nautobot_database_ready` signal for one-time database initialization

5. **Configuration via Constance**: Use database-backed configuration that can be changed at runtime

### Decision Matrix

| Requirement | Recommended Approach |
|-------------|---------------------|
| Event-driven background work | Jobs Framework |
| Persistent TCP/UDP listener | External Service (sidecar) |
| One-time database setup | `nautobot_database_ready` signal |
| Configuration management | Constance + Jobs |
| Long-running tasks | Jobs with soft time limits |
| Inter-service communication | REST API + webhooks |

### Questions?

For questions about NTC-approved patterns, consult:
- [Network to Code GitHub](https://github.com/nautobot)
- [Nautobot Slack Community](https://networktocode.slack.com/)
- [Nautobot Documentation](https://docs.nautobot.com/)

---

*Last Updated: 2026-02-03*
*Author: Nautobot Development Team*
