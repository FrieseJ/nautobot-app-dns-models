"""Test ZoneTransferACL model."""

import base64
import ipaddress

from django.core.exceptions import ValidationError
from nautobot.apps.testing import ModelTestCases

from nautobot_dns_models.models import (
    ACLActionChoices,
    DNSView,
    DNSZone,
    TSIGKey,
    ZoneTransferACL,
)


class TestZoneTransferACL(ModelTestCases.BaseModelTestCase):
    """Test ZoneTransferACL model."""

    model = ZoneTransferACL

    @classmethod
    def setUpTestData(cls):
        """Create test data for ZoneTransferACL Model."""
        super().setUpTestData()

        # Create DNS View and Zones for testing
        cls.dns_view = DNSView.objects.create(name="TestView", description="Test DNS View")
        cls.zone1 = DNSZone.objects.create(
            name="example.com",
            dns_view=cls.dns_view,
            filename="db.example.com",
            soa_mname="ns1.example.com",
            soa_rname="admin@example.com",
        )
        cls.zone2 = DNSZone.objects.create(
            name="test.com",
            dns_view=cls.dns_view,
            filename="db.test.com",
            soa_mname="ns1.test.com",
            soa_rname="admin@test.com",
        )

        # Create a TSIG key for testing
        cls.tsig_key = TSIGKey.objects.create(
            name="test-key.example.com",
            secret=base64.b64encode(b"test_secret").decode("ascii"),
        )

        # Create exactly 3 test objects (NTC requirement)
        cls.acl1 = ZoneTransferACL.objects.create(
            name="Allow Trusted Network",
            ip_address="10.0.0.0",
            prefix_length=8,
            action=ACLActionChoices.ALLOW,
            priority=10,
            description="Allow internal network",
            is_active=True,
        )
        cls.acl2 = ZoneTransferACL.objects.create(
            name="Allow Specific Server",
            ip_address="203.0.113.50",
            action=ACLActionChoices.ALLOW,
            priority=5,
            description="Allow secondary DNS server",
            is_active=True,
        )
        cls.acl3 = ZoneTransferACL.objects.create(
            name="Deny Untrusted",
            ip_address="192.168.1.0",
            prefix_length=24,
            action=ACLActionChoices.DENY,
            priority=100,
            description="Deny untrusted network",
            is_active=False,
        )

    def test_create_acl_only_required(self):
        """Create ZoneTransferACL with only required fields."""
        acl = ZoneTransferACL.objects.create(
            name="Minimal ACL",
            ip_address="198.51.100.1",
        )
        self.assertEqual(acl.name, "Minimal ACL")
        self.assertEqual(acl.ip_address, "198.51.100.1")
        self.assertIsNone(acl.prefix_length)
        self.assertEqual(acl.action, ACLActionChoices.ALLOW)  # default
        self.assertEqual(acl.priority, 100)  # default
        self.assertTrue(acl.is_active)  # default
        self.assertEqual(acl.description, "")

    def test_create_acl_all_fields(self):
        """Create ZoneTransferACL with all fields."""
        acl = ZoneTransferACL.objects.create(
            name="Full ACL",
            ip_address="10.1.2.0",
            prefix_length=24,
            action=ACLActionChoices.DENY,
            priority=50,
            description="Full test ACL",
            is_active=True,
            tsig_key=self.tsig_key,
        )
        acl.zones.add(self.zone1)

        self.assertEqual(acl.name, "Full ACL")
        self.assertEqual(acl.ip_address, "10.1.2.0")
        self.assertEqual(acl.prefix_length, 24)
        self.assertEqual(acl.action, ACLActionChoices.DENY)
        self.assertEqual(acl.priority, 50)
        self.assertEqual(acl.description, "Full test ACL")
        self.assertTrue(acl.is_active)
        self.assertEqual(acl.tsig_key, self.tsig_key)
        self.assertIn(self.zone1, acl.zones.all())

    def test_acl_str_representation_global(self):
        """Test __str__ method for global ACL."""
        acl = ZoneTransferACL.objects.create(
            name="Test ACL",
            ip_address="10.0.0.0",
            prefix_length=8,
            action=ACLActionChoices.ALLOW,
        )
        # Should show "global" since no zones assigned
        str_repr = str(acl)
        self.assertIn("Test ACL", str_repr)
        self.assertIn("[Allow]", str_repr)
        self.assertIn("10.0.0.0/8", str_repr)
        self.assertIn("global", str_repr)

    def test_acl_str_representation_with_zones(self):
        """Test __str__ method for zone-specific ACL."""
        acl = ZoneTransferACL.objects.create(
            name="Zone ACL",
            ip_address="192.0.2.1",
            action=ACLActionChoices.DENY,
        )
        acl.zones.add(self.zone1, self.zone2)

        str_repr = str(acl)
        self.assertIn("Zone ACL", str_repr)
        self.assertIn("[Deny]", str_repr)
        self.assertIn("192.0.2.1", str_repr)
        self.assertIn("2 zone(s)", str_repr)

    def test_get_absolute_url(self):
        """Test get_absolute_url method."""
        self.assertEqual(
            self.acl1.get_absolute_url(),
            f"/plugins/dns/zone-transfer-acls/{self.acl1.pk}/"
        )

    def test_get_network_display_cidr(self):
        """Test get_network_display with CIDR notation."""
        self.assertEqual(self.acl1.get_network_display(), "10.0.0.0/8")

    def test_get_network_display_single_host(self):
        """Test get_network_display for single host."""
        self.assertEqual(self.acl2.get_network_display(), "203.0.113.50")

    def test_matches_ip_single_host_match(self):
        """Test IP matching for single host - exact match."""
        self.assertTrue(self.acl2.matches_ip("203.0.113.50"))

    def test_matches_ip_single_host_no_match(self):
        """Test IP matching for single host - no match."""
        self.assertFalse(self.acl2.matches_ip("203.0.113.51"))

    def test_matches_ip_network_match(self):
        """Test IP matching for network - IP in range."""
        self.assertTrue(self.acl1.matches_ip("10.5.10.20"))
        self.assertTrue(self.acl1.matches_ip("10.255.255.255"))

    def test_matches_ip_network_no_match(self):
        """Test IP matching for network - IP not in range."""
        self.assertFalse(self.acl1.matches_ip("192.168.1.1"))
        self.assertFalse(self.acl1.matches_ip("11.0.0.1"))

    def test_matches_ip_string_input(self):
        """Test IP matching with string input."""
        self.assertTrue(self.acl1.matches_ip("10.0.0.1"))

    def test_matches_ip_ipaddress_object(self):
        """Test IP matching with ipaddress object input."""
        ip_obj = ipaddress.ip_address("10.0.0.1")
        self.assertTrue(self.acl1.matches_ip(ip_obj))

    def test_matches_ip_inactive_acl(self):
        """Test that inactive ACLs don't match."""
        # acl3 is inactive
        self.assertFalse(self.acl3.matches_ip("192.168.1.50"))

    def test_matches_ip_invalid_input(self):
        """Test IP matching with invalid input."""
        self.assertFalse(self.acl1.matches_ip("not-an-ip"))
        self.assertFalse(self.acl1.matches_ip(None))

    def test_matches_ip_ipv4_network_24(self):
        """Test IPv4 /24 network matching."""
        acl = ZoneTransferACL.objects.create(
            name="IPv4 /24",
            ip_address="192.168.1.0",
            prefix_length=24,
            action=ACLActionChoices.ALLOW,
        )
        self.assertTrue(acl.matches_ip("192.168.1.1"))
        self.assertTrue(acl.matches_ip("192.168.1.255"))
        self.assertFalse(acl.matches_ip("192.168.2.1"))

    def test_matches_ip_ipv4_network_32(self):
        """Test IPv4 /32 (single host) matching."""
        acl = ZoneTransferACL.objects.create(
            name="IPv4 /32",
            ip_address="192.0.2.100",
            prefix_length=32,
            action=ACLActionChoices.ALLOW,
        )
        self.assertTrue(acl.matches_ip("192.0.2.100"))
        self.assertFalse(acl.matches_ip("192.0.2.101"))

    def test_matches_ip_ipv6_single_host(self):
        """Test IPv6 single host matching."""
        acl = ZoneTransferACL.objects.create(
            name="IPv6 Host",
            ip_address="2001:db8::1",
            action=ACLActionChoices.ALLOW,
        )
        self.assertTrue(acl.matches_ip("2001:db8::1"))
        self.assertFalse(acl.matches_ip("2001:db8::2"))

    def test_matches_ip_ipv6_network(self):
        """Test IPv6 network matching."""
        acl = ZoneTransferACL.objects.create(
            name="IPv6 Network",
            ip_address="2001:db8::",
            prefix_length=32,
            action=ACLActionChoices.ALLOW,
        )
        self.assertTrue(acl.matches_ip("2001:db8::1"))
        self.assertTrue(acl.matches_ip("2001:db8:ffff:ffff::1"))
        self.assertFalse(acl.matches_ip("2001:db9::1"))

    def test_applies_to_zone_global_acl(self):
        """Test applies_to_zone for global ACL (no zones)."""
        # acl1 has no zones, so it's global
        self.assertTrue(self.acl1.applies_to_zone(self.zone1))
        self.assertTrue(self.acl1.applies_to_zone(self.zone2))

    def test_applies_to_zone_specific_zone(self):
        """Test applies_to_zone for zone-specific ACL."""
        self.acl2.zones.add(self.zone1)

        self.assertTrue(self.acl2.applies_to_zone(self.zone1))
        self.assertFalse(self.acl2.applies_to_zone(self.zone2))

    def test_applies_to_zone_inactive_acl(self):
        """Test that inactive ACLs don't apply."""
        # acl3 is inactive
        self.assertFalse(self.acl3.applies_to_zone(self.zone1))

    def test_get_ordered_acls_no_filters(self):
        """Test get_ordered_acls without filters."""
        acls = ZoneTransferACL.get_ordered_acls(active_only=True)
        acl_list = list(acls)

        # Should include active ACLs in priority order
        self.assertIn(self.acl1, acl_list)
        self.assertIn(self.acl2, acl_list)
        self.assertNotIn(self.acl3, acl_list)  # inactive

        # Check ordering by priority (lower = higher priority)
        priorities = [acl.priority for acl in acl_list]
        self.assertEqual(priorities, sorted(priorities))

    def test_get_ordered_acls_with_zone_filter(self):
        """Test get_ordered_acls filtered by zone."""
        # Create zone-specific ACL
        zone_acl = ZoneTransferACL.objects.create(
            name="Zone Specific",
            ip_address="198.51.100.1",
            action=ACLActionChoices.ALLOW,
            priority=15,
        )
        zone_acl.zones.add(self.zone1)

        acls = list(ZoneTransferACL.get_ordered_acls(zone=self.zone1, active_only=True))

        # Should include global ACLs and zone-specific ACLs
        self.assertIn(self.acl1, acls)  # global
        self.assertIn(self.acl2, acls)  # global
        self.assertIn(zone_acl, acls)  # zone1-specific

    def test_get_ordered_acls_include_inactive(self):
        """Test get_ordered_acls with active_only=False."""
        acls = list(ZoneTransferACL.get_ordered_acls(active_only=False))
        self.assertIn(self.acl3, acls)  # inactive should be included

    def test_check_access_allow(self):
        """Test check_access returns ALLOW for matching IP."""
        allowed, matched_acl, reason = ZoneTransferACL.check_access(
            client_ip="10.5.10.20",
            zone=None,
            tsig_key=None
        )
        self.assertTrue(allowed)
        self.assertEqual(matched_acl, self.acl1)
        self.assertIn("Allow", reason)

    def test_check_access_deny(self):
        """Test check_access returns DENY for matching DENY rule."""
        deny_acl = ZoneTransferACL.objects.create(
            name="Deny Test",
            ip_address="172.16.0.0",
            prefix_length=12,
            action=ACLActionChoices.DENY,
            priority=5,
        )

        allowed, matched_acl, reason = ZoneTransferACL.check_access(
            client_ip="172.16.50.1",
            zone=None,
            tsig_key=None
        )
        self.assertFalse(allowed)
        self.assertEqual(matched_acl, deny_acl)
        self.assertIn("Deny", reason)

    def test_check_access_no_match_default_deny(self):
        """Test check_access returns default deny when no ACL matches."""
        allowed, matched_acl, reason = ZoneTransferACL.check_access(
            client_ip="99.99.99.99",  # Doesn't match any ACL
            zone=None,
            tsig_key=None
        )
        self.assertFalse(allowed)
        self.assertIsNone(matched_acl)
        self.assertIn("No matching ACL", reason)

    def test_check_access_priority_order(self):
        """Test that check_access respects priority order (first match wins)."""
        # Create overlapping ACLs with different priorities
        deny_broad = ZoneTransferACL.objects.create(
            name="Deny Broad",
            ip_address="10.0.0.0",
            prefix_length=8,
            action=ACLActionChoices.DENY,
            priority=100,
        )
        allow_specific = ZoneTransferACL.objects.create(
            name="Allow Specific",
            ip_address="10.1.0.0",
            prefix_length=16,
            action=ACLActionChoices.ALLOW,
            priority=10,  # Higher priority (lower number)
        )

        # IP matches both, but higher priority (lower number) should win
        allowed, matched_acl, reason = ZoneTransferACL.check_access(
            client_ip="10.1.5.20",
            zone=None,
            tsig_key=None
        )
        self.assertTrue(allowed)
        self.assertEqual(matched_acl, allow_specific)

    def test_check_access_with_zone_filter(self):
        """Test check_access with zone filtering."""
        zone_acl = ZoneTransferACL.objects.create(
            name="Zone1 Only",
            ip_address="203.0.113.100",
            action=ACLActionChoices.ALLOW,
            priority=1,
        )
        zone_acl.zones.add(self.zone1)

        # Should match for zone1
        allowed, matched_acl, reason = ZoneTransferACL.check_access(
            client_ip="203.0.113.100",
            zone=self.zone1,
            tsig_key=None
        )
        self.assertTrue(allowed)
        self.assertEqual(matched_acl, zone_acl)

        # Should not match for zone2 (different zone)
        allowed, matched_acl, reason = ZoneTransferACL.check_access(
            client_ip="203.0.113.100",
            zone=self.zone2,
            tsig_key=None
        )
        self.assertFalse(allowed)  # default deny

    def test_check_access_with_tsig_requirement(self):
        """Test check_access with TSIG key requirement."""
        acl_with_tsig = ZoneTransferACL.objects.create(
            name="Requires TSIG",
            ip_address="198.18.0.0",
            prefix_length=15,
            action=ACLActionChoices.ALLOW,
            priority=5,
            tsig_key=self.tsig_key,
        )

        # IP matches but no TSIG key provided - should not match
        allowed, matched_acl, reason = ZoneTransferACL.check_access(
            client_ip="198.18.5.10",
            zone=None,
            tsig_key=None
        )
        self.assertFalse(allowed)

        # IP matches and correct TSIG key provided - should match
        allowed, matched_acl, reason = ZoneTransferACL.check_access(
            client_ip="198.18.5.10",
            zone=None,
            tsig_key=self.tsig_key
        )
        self.assertTrue(allowed)
        self.assertEqual(matched_acl, acl_with_tsig)

    def test_check_access_with_wrong_tsig_key(self):
        """Test check_access with wrong TSIG key."""
        acl_with_tsig = ZoneTransferACL.objects.create(
            name="Requires TSIG",
            ip_address="198.18.0.0",
            prefix_length=15,
            action=ACLActionChoices.ALLOW,
            priority=5,
            tsig_key=self.tsig_key,
        )

        other_key = TSIGKey.objects.create(
            name="other-key.example.com",
            secret=base64.b64encode(b"other_secret").decode("ascii"),
        )

        # IP matches but wrong TSIG key - should not match
        allowed, matched_acl, reason = ZoneTransferACL.check_access(
            client_ip="198.18.5.10",
            zone=None,
            tsig_key=other_key
        )
        self.assertFalse(allowed)

    def test_clean_valid_ipv4_single_host(self):
        """Test validation accepts valid IPv4 single host."""
        acl = ZoneTransferACL(
            name="Test",
            ip_address="192.0.2.1",
            action=ACLActionChoices.ALLOW,
        )
        acl.clean()  # Should not raise

    def test_clean_valid_ipv4_network(self):
        """Test validation accepts valid IPv4 network."""
        acl = ZoneTransferACL(
            name="Test",
            ip_address="192.0.2.0",
            prefix_length=24,
            action=ACLActionChoices.ALLOW,
        )
        acl.clean()  # Should not raise

    def test_clean_valid_ipv6_single_host(self):
        """Test validation accepts valid IPv6 single host."""
        acl = ZoneTransferACL(
            name="Test",
            ip_address="2001:db8::1",
            action=ACLActionChoices.ALLOW,
        )
        acl.clean()  # Should not raise

    def test_clean_valid_ipv6_network(self):
        """Test validation accepts valid IPv6 network."""
        acl = ZoneTransferACL(
            name="Test",
            ip_address="2001:db8::",
            prefix_length=32,
            action=ACLActionChoices.ALLOW,
        )
        acl.clean()  # Should not raise

    def test_clean_invalid_ipv4_prefix_too_large(self):
        """Test validation rejects IPv4 prefix > 32."""
        acl = ZoneTransferACL(
            name="Test",
            ip_address="192.0.2.0",
            prefix_length=33,  # Invalid for IPv4
            action=ACLActionChoices.ALLOW,
        )
        with self.assertRaises(ValidationError) as context:
            acl.clean()
        self.assertIn("prefix_length", context.exception.message_dict)

    def test_clean_invalid_ipv6_prefix_too_large(self):
        """Test validation rejects IPv6 prefix > 128."""
        acl = ZoneTransferACL(
            name="Test",
            ip_address="2001:db8::",
            prefix_length=129,  # Invalid for IPv6
            action=ACLActionChoices.ALLOW,
        )
        with self.assertRaises(ValidationError) as context:
            acl.clean()
        self.assertIn("prefix_length", context.exception.message_dict)

    def test_clean_invalid_ip_address(self):
        """Test validation rejects invalid IP address."""
        acl = ZoneTransferACL(
            name="Test",
            ip_address="not-an-ip",
            action=ACLActionChoices.ALLOW,
        )
        with self.assertRaises(ValidationError):
            acl.clean()

    def test_save_calls_clean(self):
        """Test that save() calls clean() for validation."""
        acl = ZoneTransferACL(
            name="Test",
            ip_address="192.0.2.0",
            prefix_length=33,  # Invalid
            action=ACLActionChoices.ALLOW,
        )
        with self.assertRaises(ValidationError):
            acl.save()

    def test_action_choices(self):
        """Test both action choices are valid."""
        allow_acl = ZoneTransferACL.objects.create(
            name="Allow ACL",
            ip_address="192.0.2.1",
            action=ACLActionChoices.ALLOW,
        )
        deny_acl = ZoneTransferACL.objects.create(
            name="Deny ACL",
            ip_address="192.0.2.2",
            action=ACLActionChoices.DENY,
        )
        self.assertEqual(allow_acl.action, ACLActionChoices.ALLOW)
        self.assertEqual(deny_acl.action, ACLActionChoices.DENY)

    def test_zones_many_to_many(self):
        """Test zones ManyToMany relationship."""
        acl = ZoneTransferACL.objects.create(
            name="M2M Test",
            ip_address="198.51.100.1",
            action=ACLActionChoices.ALLOW,
        )

        # Add zones
        acl.zones.add(self.zone1, self.zone2)
        self.assertEqual(acl.zones.count(), 2)
        self.assertIn(self.zone1, acl.zones.all())
        self.assertIn(self.zone2, acl.zones.all())

        # Remove a zone
        acl.zones.remove(self.zone1)
        self.assertEqual(acl.zones.count(), 1)

    def test_reverse_relationship_from_zone(self):
        """Test reverse relationship from DNSZone to ZoneTransferACL."""
        self.acl1.zones.add(self.zone1)

        # Access ACLs from zone
        acls = self.zone1.zone_transfer_acls.all()
        self.assertIn(self.acl1, acls)

    def test_priority_range_validation(self):
        """Test priority validation (0-9999)."""
        # Valid priorities
        acl_min = ZoneTransferACL.objects.create(
            name="Min Priority",
            ip_address="192.0.2.1",
            priority=0,
            action=ACLActionChoices.ALLOW,
        )
        acl_max = ZoneTransferACL.objects.create(
            name="Max Priority",
            ip_address="192.0.2.2",
            priority=9999,
            action=ACLActionChoices.ALLOW,
        )
        self.assertEqual(acl_min.priority, 0)
        self.assertEqual(acl_max.priority, 9999)

    def test_tsig_key_foreign_key_set_null(self):
        """Test that deleting TSIG key sets ACL tsig_key to NULL."""
        key = TSIGKey.objects.create(
            name="temp-key.example.com",
            secret=base64.b64encode(b"temp").decode("ascii"),
        )
        acl = ZoneTransferACL.objects.create(
            name="ACL with Key",
            ip_address="203.0.113.1",
            action=ACLActionChoices.ALLOW,
            tsig_key=key,
        )

        key.delete()
        acl.refresh_from_db()

        # Should be NULL after key deletion (on_delete=SET_NULL)
        self.assertIsNone(acl.tsig_key)

    def test_multiple_acls_same_ip_different_zones(self):
        """Test multiple ACLs can have same IP for different zones."""
        acl_zone1 = ZoneTransferACL.objects.create(
            name="Zone1 ACL",
            ip_address="203.0.113.1",
            action=ACLActionChoices.ALLOW,
            priority=10,
        )
        acl_zone2 = ZoneTransferACL.objects.create(
            name="Zone2 ACL",
            ip_address="203.0.113.1",
            action=ACLActionChoices.DENY,
            priority=20,
        )

        acl_zone1.zones.add(self.zone1)
        acl_zone2.zones.add(self.zone2)

        # Check access for zone1
        allowed, matched_acl, _ = ZoneTransferACL.check_access(
            client_ip="203.0.113.1",
            zone=self.zone1,
            tsig_key=None
        )
        self.assertTrue(allowed)
        self.assertEqual(matched_acl, acl_zone1)

        # Check access for zone2
        allowed, matched_acl, _ = ZoneTransferACL.check_access(
            client_ip="203.0.113.1",
            zone=self.zone2,
            tsig_key=None
        )
        self.assertFalse(allowed)
        self.assertEqual(matched_acl, acl_zone2)
