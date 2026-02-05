"""Models for Nautobot DNS Models."""

import base64
import ipaddress
import secrets

from constance import config as constance_config
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django_cryptography.fields import encrypt
from nautobot.apps.models import BaseModel, PrimaryModel, extras_features
from nautobot.core.models.fields import ForeignKeyWithAutoRelatedName
from nautobot.ipam.choices import IPAddressVersionChoices


def dns_wire_label_length(label):
    """Return the wire-format (IDNA/Punycode) length of a DNS label."""
    if label.isascii():
        return len(label)

    return len("xn--" + label.encode("punycode").decode("ascii"))


class TSIGAlgorithmChoices(models.TextChoices):
    """TSIG algorithm choices."""

    HMAC_SHA256 = "hmac-sha256", "HMAC-SHA256"
    HMAC_SHA384 = "hmac-sha384", "HMAC-SHA384"
    HMAC_SHA512 = "hmac-sha512", "HMAC-SHA512"
    HMAC_MD5 = "hmac-md5", "HMAC-MD5"


class ACLActionChoices(models.TextChoices):
    """ACL action choices."""

    ALLOW = "allow", "Allow"
    DENY = "deny", "Deny"


class DNSModel(PrimaryModel):
    """Abstract Model for Nautobot DNS Models."""

    #
    # name is effectively a NOOP here; it's overridden in both subclasses but
    # is here so that linters don't complain about it being used in clean().
    name = models.CharField(max_length=200)
    ttl = models.IntegerField(
        validators=[MinValueValidator(300), MaxValueValidator(2147483647)], default=3600, help_text="Time To Live."
    )

    class Meta:
        """Meta class."""

        abstract = True

    def __str__(self):
        """Stringify instance."""
        return self.name  # pylint: disable=no-member

    @staticmethod
    def _validate_dns_label(label, field="name"):
        """
        Validate a DNS label for wire-format length using punycode encoding.

        Only checks for non-empty and length.
        """
        if not label:
            raise ValidationError({field: "Empty labels are not allowed"})
        length = dns_wire_label_length(label)
        if length > 63:
            raise ValidationError(
                {field: f"Label '{label}' exceeds the maximum length of 63 bytes (octets) in wire format."}
            )
        return length

    def clean(self):
        """
        Validate DNS label length and format per RFC 1035 §3.1 using punycode for wire-format length.

        Ensures each label in the name is ≤ 63 bytes (octets) in wire format and not empty.
        """
        super().clean()

        validation_level = getattr(constance_config, "nautobot_dns_models__DNS_VALIDATION_LEVEL")
        if validation_level == "wire-format":
            # Allow apex (empty) names; otherwise validate each non-empty label.
            if self.name != "":
                label_list = self.name.split(".")
                for label in label_list:
                    self._validate_dns_label(label, field="name")


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class DNSView(PrimaryModel):
    """Model for DNS Views."""

    name = models.CharField(max_length=200, help_text="Name of the View.", unique=True)
    description = models.TextField(help_text="Description of the View.", blank=True)
    prefixes = models.ManyToManyField(
        to="ipam.Prefix",
        related_name="dns_views",
        through="DNSViewPrefixAssignment",
        through_fields=("dns_view", "prefix"),
        blank=True,
        help_text="IP Prefixes that define the View.",
    )

    class Meta:
        """Meta attributes for DNSView."""

        verbose_name = "DNS View"
        verbose_name_plural = "DNS Views"

    def __str__(self):
        """Stringify instance."""
        return self.name


@extras_features("graphql")
class DNSViewPrefixAssignment(BaseModel):
    """Through model for DNSView and Prefix many-to-many relationship."""

    dns_view = ForeignKeyWithAutoRelatedName(
        DNSView,
        on_delete=models.CASCADE,
    )
    prefix = ForeignKeyWithAutoRelatedName(to="ipam.Prefix", on_delete=models.CASCADE)

    class Meta:
        """Meta attributes for DNSViewPrefixAssignment."""

        unique_together = [["dns_view", "prefix"]]
        verbose_name = "DNS View Prefix Assignment"
        verbose_name_plural = "DNS View Prefix Assignments"

    def __str__(self):
        """Stringify instance."""
        return f"{self.dns_view}: {self.prefix}"


def get_default_view_pk():
    """Return the default DNSView ID, creating it if necessary."""
    default_view, _ = DNSView.objects.get_or_create(
        name="Default", defaults={"description": "Default DNS view. Created by Nautobot DNS Models app."}
    )
    return default_view.pk


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class DNSZone(DNSModel):
    """Model for DNS SOA Records. An SOA Record defines a DNS Zone."""

    name = models.CharField(max_length=200, help_text="FQDN of the Zone, w/ TLD. e.g example.com")
    dns_view = ForeignKeyWithAutoRelatedName(
        DNSView,
        on_delete=models.PROTECT,
        help_text="The DNS View this Zone belongs to.",
        verbose_name="View",
        default=get_default_view_pk,
    )
    ttl = models.IntegerField(
        validators=[MinValueValidator(300), MaxValueValidator(2147483647)],
        default=3600,
        help_text="Time To Live.",
        verbose_name="TTL",
    )
    filename = models.CharField(max_length=200, help_text="Filename of the Zone File.")
    description = models.TextField(help_text="Description of the Zone.", blank=True)
    soa_mname = models.CharField(
        max_length=200,
        help_text="FQDN of the Authoritative Name Server for Zone.",
        null=False,
        verbose_name="SOA MNAME",
    )
    soa_rname = models.EmailField(help_text="Admin Email for the Zone in the form", verbose_name="SOA RNAME")
    soa_refresh = models.IntegerField(
        validators=[MinValueValidator(300), MaxValueValidator(2147483647)],
        default=86400,
        help_text="Number of seconds after which secondary name servers should query the master for the SOA record, to detect zone changes.",
        verbose_name="SOA Refresh",
    )
    soa_retry = models.IntegerField(
        validators=[MinValueValidator(300), MaxValueValidator(2147483647)],
        default=7200,
        help_text="Number of seconds after which secondary name servers should retry to request the serial number from the master if the master does not respond.",
        verbose_name="SOA Retry",
    )
    soa_expire = models.IntegerField(
        validators=[MinValueValidator(300), MaxValueValidator(2147483647)],
        default=3600000,
        help_text="Number of seconds after which secondary name servers should stop answering request for this zone if the master does not respond. This value must be bigger than the sum of Refresh and Retry.",
        verbose_name="SOA Expire",
    )
    soa_serial = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(2147483647)],
        default=0,
        help_text="Serial number of the zone. This value must be incremented each time the zone is changed, and secondary DNS servers must be able to retrieve this value to check if the zone has been updated.",
        verbose_name="SOA Serial",
    )
    soa_minimum = models.IntegerField(
        validators=[MinValueValidator(300), MaxValueValidator(2147483647)],
        default=3600,
        help_text="Minimum TTL for records in this zone.",
        verbose_name="SOA Minimum",
    )

    tenant = models.ForeignKey(
        to="tenancy.Tenant",
        on_delete=models.PROTECT,
        related_name="dns_zones",
        blank=True,
        null=True,
    )

    class Meta:
        """Meta attributes for DNSZone."""

        unique_together = [["name", "dns_view"]]
        verbose_name = "DNS Zone"
        verbose_name_plural = "DNS Zones"


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class TSIGKey(PrimaryModel):
    """
    TSIG (Transaction Signature) Key model for DNS zone transfer authentication.

    Implements RFC 2845 (TSIG) and RFC 4635 (HMAC SHA TSIG Algorithm Identifiers).
    Stores cryptographic keys for authenticating DNS zone transfer requests (AXFR/IXFR).
    """

    # Key length in bits for each algorithm
    KEY_LENGTHS = {
        TSIGAlgorithmChoices.HMAC_SHA256: 256,
        TSIGAlgorithmChoices.HMAC_SHA384: 384,
        TSIGAlgorithmChoices.HMAC_SHA512: 512,
        TSIGAlgorithmChoices.HMAC_MD5: 128,
    }

    name = models.CharField(
        max_length=200,
        unique=True,
        help_text="TSIG key name in DNS format (e.g., 'transfer-key.example.com'). Must be unique.",
        verbose_name="Key Name",
    )

    algorithm = models.CharField(
        max_length=50,
        choices=TSIGAlgorithmChoices.choices,
        default=TSIGAlgorithmChoices.HMAC_SHA256,
        help_text="HMAC algorithm for TSIG signature generation and verification.",
        verbose_name="Algorithm",
    )

    # Encrypted field for secret storage
    secret = encrypt(
        models.CharField(
            max_length=500,
            help_text="Base64-encoded TSIG secret key. Stored encrypted in database.",
            verbose_name="Secret Key",
        )
    )

    description = models.TextField(
        blank=True,
        help_text="Optional description of this TSIG key's purpose or usage.",
        verbose_name="Description",
    )

    zones = models.ManyToManyField(
        to="DNSZone",
        related_name="tsig_keys",
        blank=True,
        help_text="DNS zones this key is authorized to transfer. Empty = global key (all zones).",
        verbose_name="Authorized Zones",
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Whether this TSIG key is active and can be used for authentication.",
        verbose_name="Active",
    )

    last_used = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp of the last successful authentication using this key.",
        verbose_name="Last Used",
    )

    class Meta:
        """Meta attributes for TSIGKey."""

        verbose_name = "TSIG Key"
        verbose_name_plural = "TSIG Keys"
        ordering = ["name"]

    def __str__(self):
        """String representation of TSIGKey."""
        return f"{self.name} ({self.algorithm})"

    def get_absolute_url(self, api=False):
        """Return the absolute URL for this TSIGKey."""
        if api:
            return f"/api/plugins/nautobot-dns-models/tsig-keys/{self.pk}/"
        return f"/plugins/dns/tsig-keys/{self.pk}/"

    def clean(self):
        """Validate TSIG key fields."""
        super().clean()

        # Validate key name format (DNS name)
        if self.name:
            # Basic DNS name validation
            if not self.name.replace("-", "").replace(".", "").replace("_", "").isalnum():
                raise ValidationError({
                    "name": "TSIG key name must be a valid DNS name (alphanumeric, hyphens, dots, underscores only)."
                })

            # Validate label length (DNS wire format)
            labels = self.name.split(".")
            for label in labels:
                if label:
                    # Check if label is empty
                    if not label:
                        raise ValidationError({"name": "Empty labels are not allowed"})
                    # Check label length
                    length = dns_wire_label_length(label)
                    if length > 63:
                        raise ValidationError({
                            "name": f"DNS label '{label}' is too long ({length} bytes in wire format, max 63)"
                        })

        # Validate secret is base64-encoded
        if self.secret:
            try:
                base64.b64decode(self.secret, validate=True)
            except Exception:
                raise ValidationError({
                    "secret": "TSIG secret must be a valid base64-encoded string."
                })

    def save(self, *args, **kwargs):
        """Override save to run validation."""
        self.clean()
        super().save(*args, **kwargs)

    @classmethod
    def generate_key(cls, name, algorithm=TSIGAlgorithmChoices.HMAC_SHA256, description=""):
        """
        Generate a new TSIG key with a cryptographically secure random secret.

        Args:
            name: Key name in DNS format
            algorithm: HMAC algorithm (default: HMAC-SHA256)
            description: Optional description

        Returns:
            TSIGKey instance (unsaved)

        Example:
            >>> key = TSIGKey.generate_key("transfer-key.example.com")
            >>> key.save()
        """
        # Get recommended key length for algorithm
        key_length_bits = cls.KEY_LENGTHS.get(algorithm, 256)
        key_length_bytes = key_length_bits // 8

        # Generate cryptographically secure random bytes
        random_bytes = secrets.token_bytes(key_length_bytes)

        # Encode as base64
        secret_b64 = base64.b64encode(random_bytes).decode("ascii")

        # Create TSIGKey instance (not saved)
        return cls(
            name=name,
            algorithm=algorithm,
            secret=secret_b64,
            description=description or f"Auto-generated {algorithm} key",
            is_active=True,
        )

    def mark_used(self):
        """Update the last_used timestamp to current time."""
        self.last_used = timezone.now()
        self.save(update_fields=["last_used"])

    def is_authorized_for_zone(self, zone):
        """
        Check if this TSIG key is authorized for a specific zone.

        Args:
            zone: DNSZone instance

        Returns:
            bool: True if authorized (global key or zone in authorized list)
        """
        if not self.is_active:
            return False

        # If no zones specified, it's a global key (authorized for all)
        if not self.zones.exists():
            return True

        # Check if zone is in authorized list
        return self.zones.filter(pk=zone.pk).exists()

    def get_secret_display(self):
        """
        Return a masked version of the secret for display purposes.

        Returns:
            str: Masked secret (e.g., "******abc123")
        """
        if not self.secret:
            return ""

        # Show last 8 characters only
        if len(self.secret) > 8:
            return f"{'*' * (len(self.secret) - 8)}{self.secret[-8:]}"
        else:
            return "*" * len(self.secret)


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "graphql",
    "relationships",
    "webhooks",
)
class ZoneTransferACL(PrimaryModel):
    """
    Access Control List entry for DNS zone transfer requests.

    Implements IP-based access control (first stage of 3-stage validation):
    1. ACL Check (IP/CIDR matching) - THIS MODEL
    2. TSIG Validation - TSIGKey model
    3. Query Type Check - Zone transfer service

    ACL entries are evaluated in priority order (lower number = higher priority).
    First matching rule determines the action (ALLOW or DENY).
    """

    name = models.CharField(
        max_length=200,
        help_text="Descriptive name for this ACL entry.",
        verbose_name="Name",
    )

    ip_address = models.GenericIPAddressField(
        protocol="both",  # IPv4 and IPv6
        help_text="Source IP address or network address for CIDR notation.",
        verbose_name="IP Address",
    )

    prefix_length = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(128)],
        help_text="CIDR prefix length (e.g., 24 for /24). Leave blank for single host.",
        verbose_name="Prefix Length",
    )

    zones = models.ManyToManyField(
        to="DNSZone",
        related_name="zone_transfer_acls",
        blank=True,
        help_text="DNS zones this ACL applies to. Empty = global (all zones).",
        verbose_name="Zones",
    )

    tsig_key = models.ForeignKey(
        to="TSIGKey",
        on_delete=models.SET_NULL,
        related_name="acl_entries",
        null=True,
        blank=True,
        help_text="Optional: Require this TSIG key in addition to IP match.",
        verbose_name="Required TSIG Key",
    )

    action = models.CharField(
        max_length=10,
        choices=ACLActionChoices.choices,
        default=ACLActionChoices.ALLOW,
        help_text="Action to take when this ACL matches.",
        verbose_name="Action",
    )

    priority = models.IntegerField(
        default=100,
        validators=[MinValueValidator(0), MaxValueValidator(9999)],
        help_text="Priority for rule evaluation. Lower values = higher priority. Range: 0-9999.",
        verbose_name="Priority",
    )

    description = models.TextField(
        blank=True,
        help_text="Optional description of this ACL entry's purpose.",
        verbose_name="Description",
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Whether this ACL entry is active and evaluated.",
        verbose_name="Active",
    )

    class Meta:
        """Meta attributes for ZoneTransferACL."""

        verbose_name = "Zone Transfer ACL"
        verbose_name_plural = "Zone Transfer ACLs"
        ordering = ["priority", "name"]
        unique_together = [["ip_address", "prefix_length", "priority"]]
        indexes = [
            models.Index(fields=["priority", "is_active"], name="acl_priority_active_idx"),
            models.Index(fields=["action"], name="acl_action_idx"),
            models.Index(fields=["is_active"], name="acl_is_active_idx"),
        ]

    def __str__(self):
        """String representation of ACL entry."""
        network = self.get_network_display()
        action = self.get_action_display()
        zone_info = "global" if not self.zones.exists() else f"{self.zones.count()} zone(s)"
        return f"{self.name} [{action}] {network} ({zone_info})"

    def get_absolute_url(self, api=False):
        """Return the absolute URL for this ACL entry."""
        if api:
            return f"/api/plugins/nautobot-dns-models/zone-transfer-acls/{self.pk}/"
        return f"/plugins/dns/zone-transfer-acls/{self.pk}/"

    def clean(self):
        """Validate ACL entry fields."""
        super().clean()

        # Validate IP address and prefix
        try:
            if self.prefix_length is not None:
                # Validate as network
                network = ipaddress.ip_network(
                    f"{self.ip_address}/{self.prefix_length}",
                    strict=False
                )

                # Check if it's IPv4 or IPv6 and validate prefix length
                if isinstance(network, ipaddress.IPv4Network):
                    if self.prefix_length > 32:
                        raise ValidationError({
                            "prefix_length": f"IPv4 prefix length must be 0-32, got {self.prefix_length}."
                        })
                elif isinstance(network, ipaddress.IPv6Network):
                    if self.prefix_length > 128:
                        raise ValidationError({
                            "prefix_length": f"IPv6 prefix length must be 0-128, got {self.prefix_length}."
                        })
            else:
                # Validate as single IP
                ipaddress.ip_address(self.ip_address)
        except ValueError as e:
            raise ValidationError({
                "ip_address": f"Invalid IP address or network: {e}"
            })

    def save(self, *args, **kwargs):
        """Override save to run validation."""
        self.clean()
        super().save(*args, **kwargs)

    def get_network_display(self):
        """
        Return human-readable network representation.

        Returns:
            str: IP/CIDR notation (e.g., "192.168.1.0/24" or "10.0.0.5")
        """
        if self.prefix_length is not None:
            return f"{self.ip_address}/{self.prefix_length}"
        return str(self.ip_address)

    def matches_ip(self, client_ip):
        """
        Check if a client IP address matches this ACL entry.

        Args:
            client_ip: IP address string or ipaddress object

        Returns:
            bool: True if IP matches this ACL entry

        Example:
            >>> acl = ZoneTransferACL(ip_address="192.168.1.0", prefix_length=24)
            >>> acl.matches_ip("192.168.1.50")
            True
            >>> acl.matches_ip("10.0.0.1")
            False
        """
        if not self.is_active:
            return False

        try:
            # Convert string to IP address object if needed
            if isinstance(client_ip, str):
                client_ip = ipaddress.ip_address(client_ip)

            # Check if this ACL is a network (CIDR) or single host
            if self.prefix_length is not None:
                # Network matching
                acl_network = ipaddress.ip_network(
                    f"{self.ip_address}/{self.prefix_length}",
                    strict=False
                )
                return client_ip in acl_network
            else:
                # Single host matching
                acl_ip = ipaddress.ip_address(self.ip_address)
                return client_ip == acl_ip

        except (ValueError, TypeError):
            # Invalid IP format
            return False

    def applies_to_zone(self, zone):
        """
        Check if this ACL applies to a specific zone.

        Args:
            zone: DNSZone instance

        Returns:
            bool: True if ACL applies (global or zone in list)
        """
        if not self.is_active:
            return False

        # Global ACL (no zones specified)
        if not self.zones.exists():
            return True

        # Check if zone is in the list
        return self.zones.filter(pk=zone.pk).exists()

    @classmethod
    def get_ordered_acls(cls, zone=None, client_ip=None, active_only=True):
        """
        Get ACL entries in evaluation order (priority ascending).

        Args:
            zone: Optional DNSZone to filter by
            client_ip: Optional IP to pre-filter matches
            active_only: Only return active ACLs (default: True)

        Returns:
            QuerySet: Ordered ACL entries

        Example:
            >>> acls = ZoneTransferACL.get_ordered_acls(zone=my_zone)
            >>> for acl in acls:
            ...     if acl.matches_ip(client_ip):
            ...         return acl.action  # First match wins
        """
        queryset = cls.objects.all()

        if active_only:
            queryset = queryset.filter(is_active=True)

        # Filter by zone if specified
        if zone:
            # Include global ACLs (no zones) and zone-specific ACLs
            queryset = queryset.filter(
                models.Q(zones__isnull=True) | models.Q(zones=zone)
            ).distinct()

        # Order by priority (lower = higher priority)
        queryset = queryset.order_by("priority", "created")

        # Prefetch related data for efficiency
        queryset = queryset.prefetch_related("zones", "tsig_key")

        return queryset

    @classmethod
    def check_access(cls, client_ip, zone=None, tsig_key=None):
        """
        Evaluate ACLs to determine if access should be granted.

        First matching ACL determines the result. If no ACL matches, default is DENY.

        Args:
            client_ip: Client IP address (string or ipaddress object)
            zone: Optional DNSZone instance
            tsig_key: Optional TSIGKey instance used for authentication

        Returns:
            tuple: (allowed: bool, matched_acl: ZoneTransferACL or None, reason: str)

        Example:
            >>> allowed, acl, reason = ZoneTransferACL.check_access(
            ...     client_ip="192.168.1.50",
            ...     zone=my_zone,
            ...     tsig_key=my_key
            ... )
            >>> if not allowed:
            ...     logger.warning(f"Access denied: {reason}")
        """
        # Get ordered ACLs applicable to this zone
        acls = cls.get_ordered_acls(zone=zone, active_only=True)

        # Evaluate each ACL in priority order
        for acl in acls:
            # Check if IP matches
            if not acl.matches_ip(client_ip):
                continue

            # Check if zone applies
            if zone and not acl.applies_to_zone(zone):
                continue

            # Check TSIG key requirement if specified
            if acl.tsig_key:
                if not tsig_key or tsig_key.pk != acl.tsig_key.pk:
                    # IP matches but wrong/missing TSIG key
                    continue

            # Match found! Return action
            allowed = acl.action == ACLActionChoices.ALLOW
            reason = f"Matched ACL '{acl.name}' (priority {acl.priority}): {acl.get_action_display()}"
            return (allowed, acl, reason)

        # No ACL matched - default deny
        return (False, None, "No matching ACL found - default deny")


class DNSRecord(DNSModel):
    """Primary Dns Record model for plugin."""

    name = models.CharField(max_length=200, help_text="FQDN of the Record, w/o TLD.")
    zone = ForeignKeyWithAutoRelatedName(DNSZone, on_delete=models.PROTECT)
    _ttl = models.IntegerField(
        validators=[MinValueValidator(300), MaxValueValidator(2147483647)],
        help_text="Time To Live (if no value is given, the Zone TTL will be used).",
        blank=True,
        null=True,
        verbose_name="TTL",
    )
    description = models.TextField(help_text="Description of the Record.", blank=True)
    comment = models.CharField(max_length=200, help_text="Comment for the Record.", blank=True)

    def clean(self):
        """
        Extend base validation to check total DNS name wire format length per RFC 1035 §3.1 using punycode for wire-format length.

        In addition to label checks, ensures the full DNS name (record + zone) does not exceed 255 bytes (octets) in wire format.
        """
        # Normalize trailing-dot only when the record name is zone-qualified (e.g., "host.example.com.")
        if (
            isinstance(self.name, str)
            and self.name.endswith(".")
            and getattr(self, "zone", None)
            and getattr(self.zone, "name", None)
            and self.name.endswith(f"{self.zone.name}.")
        ):
            self.name = self.name[:-1]

        super().clean()

        if not hasattr(self, "zone"):
            raise ValidationError({"zone": "Zone is required"})

        self._validate_total_wire_length_if_enabled()
        self._enforce_cname_exclusivity_if_enabled()

    def _validate_total_wire_length_if_enabled(self) -> None:
        """Validate full DNS name (record + zone) total wire-format length if wire-format validation is enabled."""
        validation_level = getattr(constance_config, "nautobot_dns_models__DNS_VALIDATION_LEVEL")
        if validation_level != "wire-format":
            return

        record_label_list = [] if self.name == "" else self.name.split(".")
        zone_label_list = self.zone.name.split(".")

        wire_length = 0
        for label in record_label_list:
            wire_length += 1 + dns_wire_label_length(label)
        for label in zone_label_list:
            wire_length += 1 + dns_wire_label_length(label)
        wire_length += 1  # Final zero-length root label

        if wire_length > 255:
            raise ValidationError({"name": "Total length of DNS name cannot exceed 255 bytes (octets) in wire format."})

    def _enforce_cname_exclusivity_if_enabled(self) -> None:
        """Enforce mutual exclusivity between CNAME and other record types for exact (name, zone) matches."""
        enforce = getattr(constance_config, "nautobot_dns_models__CNAME_RESTRICTION_ENABLED", True)
        if not enforce or getattr(self, "name", None) is None or getattr(self, "zone_id", None) is None:
            return

        if isinstance(self, CNAMERecord):
            conflicting_models = (NSRecord, ARecord, AAAARecord, MXRecord, TXTRecord, PTRRecord, SRVRecord)
            for model in conflicting_models:
                if model.objects.filter(name=self.name, zone_id=self.zone_id).exists():
                    raise ValidationError(
                        {"name": "CNAME cannot co-exist with other records of the same name in this zone."}
                    )
        else:
            if CNAMERecord.objects.filter(name=self.name, zone_id=self.zone_id).exists():
                raise ValidationError({"name": "Record cannot co-exist with a CNAME of the same name in this zone."})

    class Meta:
        """Meta attributes for DnsRecord."""

        abstract = True

    @property
    def ttl(self):
        """Return the TTL value for the record."""
        if not self._ttl:
            return self.zone.ttl  # pylint: disable=no-member
        return self._ttl

    @ttl.setter
    def ttl(self, value):
        """Set the TTL value for the record."""
        self._ttl = value


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "relationships",
    "webhooks",
)
class NSRecord(DNSRecord):
    """NS Record model."""

    server = models.CharField(max_length=200, help_text="FQDN of an authoritative Name Server.")

    class Meta:
        """Meta attributes for NSRecord."""

        unique_together = [["name", "server", "zone"]]
        verbose_name = "NS Record"
        verbose_name_plural = "NS Records"


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "relationships",
    "webhooks",
)
class ARecord(DNSRecord):
    """A Record model."""

    ip_address = models.ForeignKey(
        to="ipam.IPAddress",
        on_delete=models.CASCADE,
        limit_choices_to={"ip_version": IPAddressVersionChoices.VERSION_4},
        help_text="IP address for the record.",
        verbose_name="IP Address",
    )

    class Meta:
        """Meta attributes for ARecord."""

        unique_together = [["name", "ip_address", "zone"]]
        verbose_name = "A Record"
        verbose_name_plural = "A Records"

    def clean(self):
        """Validate that the referenced IP address is IPv4.

        Guard against dereferencing the relation when it's unset to avoid
        RelatedObjectDoesNotExist during form/model validation.
        """
        super().clean()
        if self.ip_address_id is None:
            return
        if self.ip_address.ip_version != IPAddressVersionChoices.VERSION_4:
            raise ValidationError({"ip_address": "ARecord must reference an IPv4 address."})

    def save(self, *args, **kwargs):
        """Ensure model validation runs on direct ORM writes."""
        self.clean()
        return super().save(*args, **kwargs)


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "relationships",
    "webhooks",
)
class AAAARecord(DNSRecord):
    """AAAA Record model."""

    ip_address = models.ForeignKey(
        to="ipam.IPAddress",
        on_delete=models.CASCADE,
        limit_choices_to={"ip_version": IPAddressVersionChoices.VERSION_6},
        help_text="IP address for the record.",
        verbose_name="IP Address",
    )

    class Meta:
        """Meta attributes for AAAARecord."""

        unique_together = [["name", "ip_address", "zone"]]
        verbose_name = "AAAA Record"
        verbose_name_plural = "AAAA Records"

    def clean(self):
        """Validate that the referenced IP address is IPv6.

        Guard against dereferencing the relation when it's unset to avoid
        RelatedObjectDoesNotExist during form/model validation.
        """
        super().clean()
        if self.ip_address_id is None:
            return
        if self.ip_address.ip_version != IPAddressVersionChoices.VERSION_6:
            raise ValidationError({"ip_address": "AAAARecord must reference an IPv6 address."})

    def save(self, *args, **kwargs):
        """Ensure model validation runs on direct ORM writes."""
        self.clean()
        return super().save(*args, **kwargs)


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "relationships",
    "webhooks",
)
class CNAMERecord(DNSRecord):
    """CNAME Record model."""

    alias = models.CharField(max_length=200, help_text="FQDN of the Alias.")

    class Meta:
        """Meta attributes for CNAMERecord."""

        unique_together = [["name", "alias", "zone"]]
        verbose_name = "CNAME Record"
        verbose_name_plural = "CNAME Records"


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "relationships",
    "webhooks",
)
class MXRecord(DNSRecord):
    """MX Record model."""

    preference = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(65535)],
        default=10,
        help_text="Preference for the MX Record.",
    )
    mail_server = models.CharField(max_length=200, help_text="FQDN of the Mail Server.")

    class Meta:
        """Meta attributes for MXRecord."""

        unique_together = [["name", "mail_server", "zone"]]
        verbose_name = "MX Record"
        verbose_name_plural = "MX Records"


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "relationships",
    "webhooks",
)
class TXTRecord(DNSRecord):
    """TXT Record model."""

    text = models.CharField(max_length=256, help_text="Text for the TXT Record.")

    class Meta:
        """Meta attributes for TXTRecord."""

        unique_together = [["name", "text", "zone"]]
        verbose_name = "TXT Record"
        verbose_name_plural = "TXT Records"


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "relationships",
    "webhooks",
)
class PTRRecord(DNSRecord):
    """PTR Record model."""

    ptrdname = models.CharField(
        max_length=200, help_text="A domain name that points to some location in the domain name space."
    )

    class Meta:
        """Meta attributes for PTRRecord."""

        unique_together = [["name", "ptrdname", "zone"]]
        verbose_name = "PTR Record"
        verbose_name_plural = "PTR Records"

    def __str__(self):
        """String representation of PTRRecord."""
        return self.ptrdname


@extras_features(
    "custom_fields",
    "custom_links",
    "custom_validators",
    "export_templates",
    "relationships",
    "webhooks",
)
class SRVRecord(DNSRecord):
    """SRV Record model."""

    priority = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(65535)],
        default=0,
        help_text="Priority of the SRV record.",
    )
    weight = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(65535)],
        default=0,
        help_text="Weight of the SRV record.",
    )
    port = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(65535)],
        help_text="Port number of the service.",
    )
    target = models.CharField(
        max_length=200,
        help_text="FQDN of the target host providing the service.",
    )

    class Meta:
        """Meta attributes for SRVRecord."""

        unique_together = [["name", "target", "port", "zone"]]
        verbose_name = "SRV Record"
        verbose_name_plural = "SRV Records"
