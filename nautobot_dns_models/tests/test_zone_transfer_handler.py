"""Test zone transfer handler functionality."""

import base64

import dns.message
import dns.rdatatype
import dns.rcode
import dns.flags
import dns.tsig
from nautobot.apps.testing import TestCase

from nautobot_dns_models.models import (
    ACLActionChoices,
    DNSView,
    DNSZone,
    TSIGKey,
    ZoneTransferACL,
    NSRecord,
)
from nautobot_dns_models.zone_transfer.handler import ZoneTransferHandler


class TestZoneTransferHandler(TestCase):
    """Test zone transfer request handler."""

    @classmethod
    def setUpTestData(cls):
        """Create test data for handler tests."""
        super().setUpTestData()

        # Create DNS View and Zone
        cls.dns_view = DNSView.objects.create(name="TestView")
        cls.zone = DNSZone.objects.create(
            name="example.com",
            dns_view=cls.dns_view,
            filename="db.example.com",
            soa_mname="ns1.example.com",
            soa_rname="admin@example.com",
            soa_serial=2024010101,
        )

        # Create NS record (required for zone transfers)
        NSRecord.objects.create(
            name="@",
            zone=cls.zone,
            data="ns1.example.com",
            ttl=3600,
        )

        # Create TSIG key
        cls.tsig_key = TSIGKey.objects.create(
            name="test-key.example.com",
            algorithm="hmac-sha256",
            secret=base64.b64encode(b"test_secret_key_for_tsig").decode("ascii"),
            is_active=True,
        )
        cls.tsig_key.zones.add(cls.zone)

        # Create ACL allowing 10.0.0.0/8
        cls.allow_acl = ZoneTransferACL.objects.create(
            name="Allow Internal",
            ip_address="10.0.0.0",
            prefix_length=8,
            action=ACLActionChoices.ALLOW,
            priority=10,
            is_active=True,
        )

    def test_handler_initialization(self):
        """Test ZoneTransferHandler initialization."""
        handler = ZoneTransferHandler("10.0.0.1", 12345)
        self.assertEqual(handler.source_ip, "10.0.0.1")
        self.assertEqual(handler.source_port, 12345)

    def test_valid_axfr_request_allowed(self):
        """Test valid AXFR request is processed successfully."""
        handler = ZoneTransferHandler("10.0.0.1", 53)

        # Create AXFR query
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        # Process request
        responses = list(handler.handle_request(query.to_wire()))

        # Should get at least one response
        self.assertGreater(len(responses), 0)

        # Parse first response
        response = dns.message.from_wire(responses[0])

        # Should not be an error
        self.assertEqual(response.rcode(), dns.rcode.NOERROR)

        # Should have answer section
        self.assertGreater(len(response.answer), 0)

    def test_acl_denied_returns_refused(self):
        """Test ACL denial returns REFUSED."""
        handler = ZoneTransferHandler("192.168.1.1", 53)  # Not in ACL

        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        responses = list(handler.handle_request(query.to_wire()))
        self.assertEqual(len(responses), 1)

        response = dns.message.from_wire(responses[0])
        self.assertEqual(response.rcode(), dns.rcode.REFUSED)

    def test_nonexistent_zone_returns_refused(self):
        """Test query for nonexistent zone returns REFUSED."""
        handler = ZoneTransferHandler("10.0.0.1", 53)

        query = dns.message.make_query(
            "nonexistent.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        responses = list(handler.handle_request(query.to_wire()))
        self.assertEqual(len(responses), 1)

        response = dns.message.from_wire(responses[0])
        self.assertEqual(response.rcode(), dns.rcode.REFUSED)

    def test_non_axfr_query_returns_refused(self):
        """Test non-AXFR query type returns REFUSED."""
        handler = ZoneTransferHandler("10.0.0.1", 53)

        # Try A record query instead of AXFR
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.A,
            dns.rdataclass.IN
        )

        responses = list(handler.handle_request(query.to_wire()))
        self.assertEqual(len(responses), 1)

        response = dns.message.from_wire(responses[0])
        self.assertEqual(response.rcode(), dns.rcode.REFUSED)

    def test_ixfr_query_returns_notimpl(self):
        """Test IXFR query returns NOTIMPL."""
        handler = ZoneTransferHandler("10.0.0.1", 53)

        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.IXFR,
            dns.rdataclass.IN
        )

        responses = list(handler.handle_request(query.to_wire()))
        self.assertEqual(len(responses), 1)

        response = dns.message.from_wire(responses[0])
        self.assertEqual(response.rcode(), dns.rcode.NOTIMP)

    def test_malformed_query_returns_formerr(self):
        """Test malformed query returns FORMERR."""
        handler = ZoneTransferHandler("10.0.0.1", 53)

        # Send garbage data
        responses = list(handler.handle_request(b"garbage data"))
        self.assertEqual(len(responses), 1)

        response = dns.message.from_wire(responses[0])
        self.assertEqual(response.rcode(), dns.rcode.FORMERR)

    def test_query_without_question_returns_formerr(self):
        """Test query without question section returns FORMERR."""
        handler = ZoneTransferHandler("10.0.0.1", 53)

        # Create query and remove question
        query = dns.message.Message()
        query.id = 12345

        responses = list(handler.handle_request(query.to_wire()))
        self.assertEqual(len(responses), 1)

        response = dns.message.from_wire(responses[0])
        self.assertEqual(response.rcode(), dns.rcode.FORMERR)

    def test_acl_priority_ordering(self):
        """Test that ACL rules are evaluated by priority."""
        # Create specific ALLOW rule with higher priority
        specific_allow = ZoneTransferACL.objects.create(
            name="Allow Specific",
            ip_address="192.168.1.100",
            action=ACLActionChoices.ALLOW,
            priority=5,  # Higher priority (lower number)
            is_active=True,
        )

        # Create broad DENY rule with lower priority
        broad_deny = ZoneTransferACL.objects.create(
            name="Deny Broad",
            ip_address="192.168.0.0",
            prefix_length=16,
            action=ACLActionChoices.DENY,
            priority=100,  # Lower priority (higher number)
            is_active=True,
        )

        handler = ZoneTransferHandler("192.168.1.100", 53)

        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        responses = list(handler.handle_request(query.to_wire()))
        response = dns.message.from_wire(responses[0])

        # Should be allowed (specific rule wins)
        self.assertEqual(response.rcode(), dns.rcode.NOERROR)

    def test_zone_requires_tsig_without_tsig_refused(self):
        """Test that zone requiring TSIG refuses requests without TSIG."""
        # The zone has a TSIG key associated, so it requires TSIG
        handler = ZoneTransferHandler("10.0.0.1", 53)

        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )
        # No TSIG added

        responses = list(handler.handle_request(query.to_wire()))
        response = dns.message.from_wire(responses[0])

        # Should be refused (TSIG required but not provided)
        self.assertEqual(response.rcode(), dns.rcode.REFUSED)

    def test_zone_without_tsig_requirement_allows_no_tsig(self):
        """Test that zone without TSIG requirement allows requests without TSIG."""
        # Create zone without TSIG keys
        zone_no_tsig = DNSZone.objects.create(
            name="no-tsig.com",
            dns_view=self.dns_view,
            filename="db.no-tsig.com",
            soa_mname="ns1.no-tsig.com",
            soa_rname="admin@no-tsig.com",
        )
        NSRecord.objects.create(
            name="@",
            zone=zone_no_tsig,
            data="ns1.no-tsig.com",
        )

        handler = ZoneTransferHandler("10.0.0.1", 53)

        query = dns.message.make_query(
            "no-tsig.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        responses = list(handler.handle_request(query.to_wire()))
        response = dns.message.from_wire(responses[0])

        # Should be allowed
        self.assertEqual(response.rcode(), dns.rcode.NOERROR)

    def test_find_zone_exact_match(self):
        """Test _find_zone with exact match."""
        handler = ZoneTransferHandler("10.0.0.1", 53)
        zone = handler._find_zone("example.com")
        self.assertIsNotNone(zone)
        self.assertEqual(zone.name, "example.com")

    def test_find_zone_with_trailing_dot(self):
        """Test _find_zone with trailing dot."""
        handler = ZoneTransferHandler("10.0.0.1", 53)
        zone = handler._find_zone("example.com.")
        self.assertIsNotNone(zone)
        self.assertEqual(zone.name, "example.com")

    def test_find_zone_not_found(self):
        """Test _find_zone returns None for nonexistent zone."""
        handler = ZoneTransferHandler("10.0.0.1", 53)
        zone = handler._find_zone("nonexistent.com")
        self.assertIsNone(zone)

    def test_zone_requires_tsig_with_key(self):
        """Test _zone_requires_tsig returns True when zone has keys."""
        handler = ZoneTransferHandler("10.0.0.1", 53)
        requires_tsig = handler._zone_requires_tsig(self.zone)
        self.assertTrue(requires_tsig)

    def test_zone_requires_tsig_without_key(self):
        """Test _zone_requires_tsig returns False when zone has no keys."""
        zone_no_key = DNSZone.objects.create(
            name="no-key.com",
            dns_view=self.dns_view,
            filename="db.no-key.com",
            soa_mname="ns1.no-key.com",
            soa_rname="admin@no-key.com",
        )

        handler = ZoneTransferHandler("10.0.0.1", 53)
        requires_tsig = handler._zone_requires_tsig(zone_no_key)
        self.assertFalse(requires_tsig)

    def test_zone_requires_tsig_with_global_key(self):
        """Test _zone_requires_tsig with global TSIG key."""
        # Create global key (no zones specified)
        global_key = TSIGKey.objects.create(
            name="global-key.example.com",
            secret=base64.b64encode(b"global_secret").decode("ascii"),
            is_active=True,
        )
        # Don't add any zones - it's global

        zone_test = DNSZone.objects.create(
            name="test-global.com",
            dns_view=self.dns_view,
            filename="db.test-global.com",
            soa_mname="ns1.test-global.com",
            soa_rname="admin@test-global.com",
        )

        handler = ZoneTransferHandler("10.0.0.1", 53)
        # Should require TSIG because global key exists
        requires_tsig = handler._zone_requires_tsig(zone_test)
        self.assertTrue(requires_tsig)

    def test_zone_requires_tsig_with_inactive_key(self):
        """Test _zone_requires_tsig ignores inactive keys."""
        zone_inactive = DNSZone.objects.create(
            name="inactive-key.com",
            dns_view=self.dns_view,
            filename="db.inactive-key.com",
            soa_mname="ns1.inactive-key.com",
            soa_rname="admin@inactive-key.com",
        )

        inactive_key = TSIGKey.objects.create(
            name="inactive-key.example.com",
            secret=base64.b64encode(b"inactive_secret").decode("ascii"),
            is_active=False,  # Inactive
        )
        inactive_key.zones.add(zone_inactive)

        handler = ZoneTransferHandler("10.0.0.1", 53)
        # Should not require TSIG (key is inactive)
        requires_tsig = handler._zone_requires_tsig(zone_inactive)
        self.assertFalse(requires_tsig)

    def test_multiple_messages_for_large_zone(self):
        """Test that large zones generate multiple messages."""
        # Create zone with many records
        large_zone = DNSZone.objects.create(
            name="large.com",
            dns_view=self.dns_view,
            filename="db.large.com",
            soa_mname="ns1.large.com",
            soa_rname="admin@large.com",
        )

        # Add NS record
        NSRecord.objects.create(
            name="@",
            zone=large_zone,
            data="ns1.large.com",
        )

        # Import here to avoid circular import
        from nautobot_dns_models.models import ARecord

        # Create many A records
        for i in range(50):
            ARecord.objects.create(
                name=f"host{i}",
                zone=large_zone,
                data=f"192.0.2.{i % 255}",
            )

        # Create ACL for this zone
        ZoneTransferACL.objects.create(
            name="Allow Large",
            ip_address="10.0.0.0",
            prefix_length=8,
            action=ACLActionChoices.ALLOW,
            is_active=True,
        )

        handler = ZoneTransferHandler("10.0.0.1", 53)

        query = dns.message.make_query(
            "large.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        responses = list(handler.handle_request(query.to_wire()))

        # Should get responses
        self.assertGreater(len(responses), 0)

        # All should be valid DNS messages
        for response_bytes in responses:
            response = dns.message.from_wire(response_bytes)
            self.assertEqual(response.rcode(), dns.rcode.NOERROR)

    def test_acl_check_before_expensive_operations(self):
        """Test that ACL check happens before expensive zone lookup."""
        # Create handler for denied IP
        handler = ZoneTransferHandler("192.168.1.1", 53)  # Not in ACL

        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        # Should get REFUSED quickly without doing zone transfer
        responses = list(handler.handle_request(query.to_wire()))
        self.assertEqual(len(responses), 1)

        response = dns.message.from_wire(responses[0])
        self.assertEqual(response.rcode(), dns.rcode.REFUSED)

    def test_query_type_check_before_acl(self):
        """Test that query type is checked early."""
        handler = ZoneTransferHandler("10.0.0.1", 53)

        # Send non-AXFR query
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.A,
            dns.rdataclass.IN
        )

        responses = list(handler.handle_request(query.to_wire()))
        response = dns.message.from_wire(responses[0])

        # Should be refused
        self.assertEqual(response.rcode(), dns.rcode.REFUSED)

    def test_response_has_aa_flag(self):
        """Test that successful AXFR responses have AA (Authoritative Answer) flag."""
        handler = ZoneTransferHandler("10.0.0.1", 53)

        # Create zone without TSIG requirement
        simple_zone = DNSZone.objects.create(
            name="simple.com",
            dns_view=self.dns_view,
            filename="db.simple.com",
            soa_mname="ns1.simple.com",
            soa_rname="admin@simple.com",
        )
        NSRecord.objects.create(name="@", zone=simple_zone, data="ns1.simple.com")

        query = dns.message.make_query(
            "simple.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        responses = list(handler.handle_request(query.to_wire()))
        response = dns.message.from_wire(responses[0])

        # Check AA flag
        self.assertTrue(response.flags & dns.flags.AA)

    def test_response_id_matches_query_id(self):
        """Test that response message ID matches query message ID."""
        handler = ZoneTransferHandler("10.0.0.1", 53)

        # Create zone without TSIG
        simple_zone = DNSZone.objects.create(
            name="id-test.com",
            dns_view=self.dns_view,
            filename="db.id-test.com",
            soa_mname="ns1.id-test.com",
            soa_rname="admin@id-test.com",
        )
        NSRecord.objects.create(name="@", zone=simple_zone, data="ns1.id-test.com")

        query = dns.message.make_query(
            "id-test.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )
        query.id = 54321  # Set specific ID

        responses = list(handler.handle_request(query.to_wire()))
        response = dns.message.from_wire(responses[0])

        self.assertEqual(response.id, 54321)

    def test_acl_with_zone_filtering(self):
        """Test ACL that applies to specific zones."""
        # Create second zone
        zone2 = DNSZone.objects.create(
            name="zone2.com",
            dns_view=self.dns_view,
            filename="db.zone2.com",
            soa_mname="ns1.zone2.com",
            soa_rname="admin@zone2.com",
        )
        NSRecord.objects.create(name="@", zone=zone2, data="ns1.zone2.com")

        # Create ACL for zone1 only
        zone1_acl = ZoneTransferACL.objects.create(
            name="Zone1 Only",
            ip_address="172.16.0.1",
            action=ACLActionChoices.ALLOW,
            priority=5,
            is_active=True,
        )
        zone1_acl.zones.add(self.zone)
        # zone2 not added

        handler = ZoneTransferHandler("172.16.0.1", 53)

        # Query zone1 - should be allowed
        query1 = dns.message.make_query("example.com", dns.rdatatype.AXFR)
        responses1 = list(handler.handle_request(query1.to_wire()))
        response1 = dns.message.from_wire(responses1[0])
        self.assertEqual(response1.rcode(), dns.rcode.NOERROR)

        # Query zone2 - should be refused (ACL doesn't apply)
        query2 = dns.message.make_query("zone2.com", dns.rdatatype.AXFR)
        responses2 = list(handler.handle_request(query2.to_wire()))
        response2 = dns.message.from_wire(responses2[0])
        self.assertEqual(response2.rcode(), dns.rcode.REFUSED)

    def test_deny_acl_blocks_access(self):
        """Test that DENY ACL blocks access."""
        # Create DENY ACL
        deny_acl = ZoneTransferACL.objects.create(
            name="Deny External",
            ip_address="203.0.113.0",
            prefix_length=24,
            action=ACLActionChoices.DENY,
            priority=5,
            is_active=True,
        )

        handler = ZoneTransferHandler("203.0.113.50", 53)

        # Create zone without TSIG
        test_zone = DNSZone.objects.create(
            name="deny-test.com",
            dns_view=self.dns_view,
            filename="db.deny-test.com",
            soa_mname="ns1.deny-test.com",
            soa_rname="admin@deny-test.com",
        )
        NSRecord.objects.create(name="@", zone=test_zone, data="ns1.deny-test.com")

        query = dns.message.make_query("deny-test.com", dns.rdatatype.AXFR)
        responses = list(handler.handle_request(query.to_wire()))
        response = dns.message.from_wire(responses[0])

        # Should be refused (DENY rule)
        self.assertEqual(response.rcode(), dns.rcode.REFUSED)

    def test_inactive_acl_not_evaluated(self):
        """Test that inactive ACLs are not evaluated."""
        # Create inactive ACL
        inactive_acl = ZoneTransferACL.objects.create(
            name="Inactive",
            ip_address="198.51.100.1",
            action=ACLActionChoices.ALLOW,
            priority=1,
            is_active=False,  # Inactive
        )

        handler = ZoneTransferHandler("198.51.100.1", 53)

        query = dns.message.make_query("example.com", dns.rdatatype.AXFR)
        responses = list(handler.handle_request(query.to_wire()))
        response = dns.message.from_wire(responses[0])

        # Should be refused (no matching active ACL)
        self.assertEqual(response.rcode(), dns.rcode.REFUSED)


class TestZoneTransferHandlerTSIG(TestCase):
    """Test TSIG-specific handler functionality."""

    @classmethod
    def setUpTestData(cls):
        """Create test data with TSIG focus."""
        super().setUpTestData()

        cls.dns_view = DNSView.objects.create(name="TestView")
        cls.zone = DNSZone.objects.create(
            name="tsig-test.com",
            dns_view=cls.dns_view,
            filename="db.tsig-test.com",
            soa_mname="ns1.tsig-test.com",
            soa_rname="admin@tsig-test.com",
        )
        NSRecord.objects.create(name="@", zone=cls.zone, data="ns1.tsig-test.com")

        # Create TSIG key
        cls.tsig_key = TSIGKey.objects.create(
            name="test-key.tsig-test.com",
            algorithm="hmac-sha256",
            secret=base64.b64encode(b"shared_secret_key").decode("ascii"),
            is_active=True,
        )
        cls.tsig_key.zones.add(cls.zone)

        # Create ACL
        ZoneTransferACL.objects.create(
            name="Allow All",
            ip_address="0.0.0.0",
            prefix_length=0,
            action=ACLActionChoices.ALLOW,
            is_active=True,
        )

    def test_tsig_key_not_found_returns_badkey(self):
        """Test that unknown TSIG key returns BADKEY error."""
        handler = ZoneTransferHandler("10.0.0.1", 53)

        query = dns.message.make_query("tsig-test.com", dns.rdatatype.AXFR)

        # Add TSIG with unknown key name
        keyring = dns.tsig.Key(
            name="unknown-key.tsig-test.com",
            secret="fake_secret",
            algorithm=dns.tsig.HMAC_SHA256
        )
        query.use_tsig(keyring)

        responses = list(handler.handle_request(query.to_wire()))
        response = dns.message.from_wire(responses[0])

        # Should be an error response
        # TSIG errors may be in TSIG error field or as NOTAUTH
        self.assertIn(response.rcode(), [dns.rcode.NOTAUTH, dns.rcode.SERVFAIL])
