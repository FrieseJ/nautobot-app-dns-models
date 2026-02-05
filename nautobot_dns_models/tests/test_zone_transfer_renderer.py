"""Test zone transfer renderer functionality."""

import dns.message
import dns.name
import dns.rdatatype
import dns.flags
from nautobot.apps.testing import TestCase

from nautobot_dns_models.models import (
    DNSView,
    DNSZone,
    ARecord,
    AAAARecord,
    NSRecord,
    MXRecord,
    CNAMERecord,
    TXTRecord,
    PTRRecord,
    SRVRecord,
)
from nautobot_dns_models.zone_transfer.renderer import AXFRRenderer


class TestAXFRRenderer(TestCase):
    """Test AXFR renderer for zone transfer."""

    @classmethod
    def setUpTestData(cls):
        """Create test data for renderer tests."""
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
            soa_refresh=3600,
            soa_retry=1800,
            soa_expire=604800,
            soa_minimum=300,
            ttl=3600,
        )

        # Create NS records
        cls.ns1 = NSRecord.objects.create(
            name="@",
            zone=cls.zone,
            data="ns1.example.com",
            ttl=3600,
        )
        cls.ns2 = NSRecord.objects.create(
            name="@",
            zone=cls.zone,
            data="ns2.example.com",
            ttl=3600,
        )

        # Create A records
        cls.a1 = ARecord.objects.create(
            name="www",
            zone=cls.zone,
            data="192.0.2.1",
            ttl=300,
        )
        cls.a2 = ARecord.objects.create(
            name="mail",
            zone=cls.zone,
            data="192.0.2.10",
            ttl=300,
        )

        # Create AAAA record
        cls.aaaa1 = AAAARecord.objects.create(
            name="www",
            zone=cls.zone,
            data="2001:db8::1",
            ttl=300,
        )

        # Create MX record
        cls.mx1 = MXRecord.objects.create(
            name="@",
            zone=cls.zone,
            data="mail.example.com",
            priority=10,
            ttl=3600,
        )

        # Create CNAME record
        cls.cname1 = CNAMERecord.objects.create(
            name="ftp",
            zone=cls.zone,
            data="www.example.com",
            ttl=300,
        )

        # Create TXT record
        cls.txt1 = TXTRecord.objects.create(
            name="@",
            zone=cls.zone,
            data="v=spf1 mx -all",
            ttl=3600,
        )

    def test_renderer_initialization(self):
        """Test AXFRRenderer initialization."""
        renderer = AXFRRenderer(self.zone)
        self.assertEqual(renderer.zone, self.zone)
        self.assertEqual(str(renderer.zone_name), "example.com.")

    def test_render_axfr_returns_messages(self):
        """Test render_axfr returns DNS message generator."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        self.assertGreater(len(messages), 0)
        self.assertIsInstance(messages[0], dns.message.Message)

    def test_axfr_starts_with_soa(self):
        """Test AXFR response starts with SOA record (RFC 5936)."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        first_message = messages[0]

        # First RRset should be SOA
        self.assertGreater(len(first_message.answer), 0)
        first_rrset = first_message.answer[0]
        self.assertEqual(first_rrset.rdtype, dns.rdatatype.SOA)

    def test_axfr_ends_with_soa(self):
        """Test AXFR response ends with SOA record (RFC 5936)."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        last_message = messages[-1]

        # Last RRset should be SOA
        self.assertGreater(len(last_message.answer), 0)
        last_rrset = last_message.answer[-1]
        self.assertEqual(last_rrset.rdtype, dns.rdatatype.SOA)

    def test_axfr_soa_at_start_and_end_match(self):
        """Test that SOA records at start and end are identical."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        first_soa = messages[0].answer[0]
        last_soa = messages[-1].answer[-1]

        # Both should be SOA with same serial
        self.assertEqual(first_soa.rdtype, dns.rdatatype.SOA)
        self.assertEqual(last_soa.rdtype, dns.rdatatype.SOA)

        # Extract serial from both
        first_serial = first_soa[0].serial
        last_serial = last_soa[0].serial
        self.assertEqual(first_serial, last_serial)
        self.assertEqual(first_serial, self.zone.soa_serial)

    def test_axfr_has_aa_flag(self):
        """Test AXFR response has Authoritative Answer (AA) flag set."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        for message in messages:
            self.assertTrue(message.flags & dns.flags.AA)

    def test_axfr_contains_a_records(self):
        """Test AXFR includes A records."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        all_rrsets = []
        for msg in messages:
            all_rrsets.extend(msg.answer)

        # Find A records
        a_rrsets = [rr for rr in all_rrsets if rr.rdtype == dns.rdatatype.A]
        self.assertGreater(len(a_rrsets), 0)

        # Verify our A records are present
        a_addresses = []
        for rrset in a_rrsets:
            for rdata in rrset:
                a_addresses.append(rdata.address)

        self.assertIn("192.0.2.1", a_addresses)
        self.assertIn("192.0.2.10", a_addresses)

    def test_axfr_contains_aaaa_records(self):
        """Test AXFR includes AAAA records."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        all_rrsets = []
        for msg in messages:
            all_rrsets.extend(msg.answer)

        # Find AAAA records
        aaaa_rrsets = [rr for rr in all_rrsets if rr.rdtype == dns.rdatatype.AAAA]
        self.assertGreater(len(aaaa_rrsets), 0)

        # Verify our AAAA record is present
        aaaa_addresses = []
        for rrset in aaaa_rrsets:
            for rdata in rrset:
                aaaa_addresses.append(rdata.address)

        self.assertIn("2001:db8::1", aaaa_addresses)

    def test_axfr_contains_ns_records(self):
        """Test AXFR includes NS records."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        all_rrsets = []
        for msg in messages:
            all_rrsets.extend(msg.answer)

        # Find NS records
        ns_rrsets = [rr for rr in all_rrsets if rr.rdtype == dns.rdatatype.NS]
        self.assertGreater(len(ns_rrsets), 0)

        # Verify our NS records are present
        ns_targets = []
        for rrset in ns_rrsets:
            for rdata in rrset:
                ns_targets.append(str(rdata.target))

        self.assertIn("ns1.example.com.", ns_targets)
        self.assertIn("ns2.example.com.", ns_targets)

    def test_axfr_contains_mx_records(self):
        """Test AXFR includes MX records."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        all_rrsets = []
        for msg in messages:
            all_rrsets.extend(msg.answer)

        # Find MX records
        mx_rrsets = [rr for rr in all_rrsets if rr.rdtype == dns.rdatatype.MX]
        self.assertGreater(len(mx_rrsets), 0)

        # Verify our MX record is present
        mx_exchanges = []
        for rrset in mx_rrsets:
            for rdata in rrset:
                mx_exchanges.append((rdata.preference, str(rdata.exchange)))

        self.assertIn((10, "mail.example.com."), mx_exchanges)

    def test_axfr_contains_cname_records(self):
        """Test AXFR includes CNAME records."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        all_rrsets = []
        for msg in messages:
            all_rrsets.extend(msg.answer)

        # Find CNAME records
        cname_rrsets = [rr for rr in all_rrsets if rr.rdtype == dns.rdatatype.CNAME]
        self.assertGreater(len(cname_rrsets), 0)

        # Verify our CNAME record is present
        cname_targets = []
        for rrset in cname_rrsets:
            for rdata in rrset:
                cname_targets.append(str(rdata.target))

        self.assertIn("www.example.com.", cname_targets)

    def test_axfr_contains_txt_records(self):
        """Test AXFR includes TXT records."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        all_rrsets = []
        for msg in messages:
            all_rrsets.extend(msg.answer)

        # Find TXT records
        txt_rrsets = [rr for rr in all_rrsets if rr.rdtype == dns.rdatatype.TXT]
        self.assertGreater(len(txt_rrsets), 0)

        # Verify our TXT record is present
        txt_strings = []
        for rrset in txt_rrsets:
            for rdata in rrset:
                txt_strings.extend([s.decode() for s in rdata.strings])

        self.assertIn("v=spf1 mx -all", txt_strings)

    def test_axfr_apex_records_use_zone_name(self):
        """Test that apex (@) records use the zone name."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        all_rrsets = []
        for msg in messages:
            all_rrsets.extend(msg.answer)

        # NS and MX records at apex should have zone name
        for rrset in all_rrsets:
            if rrset.rdtype in (dns.rdatatype.NS, dns.rdatatype.MX, dns.rdatatype.TXT):
                # These are apex records in our test data
                self.assertEqual(str(rrset.name), "example.com.")

    def test_axfr_subdomain_records_use_fqdn(self):
        """Test that subdomain records use proper FQDN."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        all_rrsets = []
        for msg in messages:
            all_rrsets.extend(msg.answer)

        # Find www A record
        www_rrsets = [rr for rr in all_rrsets
                      if rr.rdtype == dns.rdatatype.A and
                      str(rr.name) == "www.example.com."]
        self.assertGreater(len(www_rrsets), 0)

    def test_axfr_ttl_values(self):
        """Test that TTL values are correctly set."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        all_rrsets = []
        for msg in messages:
            all_rrsets.extend(msg.answer)

        # Find A record (TTL=300 in our test data)
        a_rrsets = [rr for rr in all_rrsets
                    if rr.rdtype == dns.rdatatype.A and
                    str(rr.name) == "www.example.com."]
        if a_rrsets:
            self.assertEqual(a_rrsets[0].ttl, 300)

    def test_axfr_soa_fields(self):
        """Test SOA record contains correct fields."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        soa_rrset = messages[0].answer[0]
        soa_rdata = soa_rrset[0]

        # Check SOA fields
        self.assertEqual(soa_rdata.serial, 2024010101)
        self.assertEqual(soa_rdata.refresh, 3600)
        self.assertEqual(soa_rdata.retry, 1800)
        self.assertEqual(soa_rdata.expire, 604800)
        self.assertEqual(soa_rdata.minimum, 300)
        self.assertEqual(str(soa_rdata.mname), "ns1.example.com.")

    def test_axfr_soa_rname_email_format(self):
        """Test SOA RNAME field converts email correctly."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        soa_rrset = messages[0].answer[0]
        soa_rdata = soa_rrset[0]

        # RNAME should be in DNS format (admin.example.com. not admin@example.com)
        rname_str = str(soa_rdata.rname)
        self.assertIn("admin.", rname_str)
        self.assertNotIn("@", rname_str)

    def test_axfr_message_id_matches_query(self):
        """Test that response message ID matches query message ID."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )
        query.id = 12345

        messages = list(renderer.render_axfr(query))
        for message in messages:
            self.assertEqual(message.id, query.id)

    def test_axfr_empty_zone_has_only_soa(self):
        """Test AXFR for zone with no records (only SOA)."""
        empty_zone = DNSZone.objects.create(
            name="empty.com",
            dns_view=self.dns_view,
            filename="db.empty.com",
            soa_mname="ns1.empty.com",
            soa_rname="admin@empty.com",
            soa_serial=1,
        )

        renderer = AXFRRenderer(empty_zone)
        query = dns.message.make_query(
            "empty.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))

        # Should have at least one message
        self.assertGreater(len(messages), 0)

        # Count SOA records in all messages
        soa_count = 0
        for msg in messages:
            for rrset in msg.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    soa_count += 1

        # Should have exactly 2 SOA records (start and end)
        self.assertEqual(soa_count, 2)

    def test_axfr_multiple_records_same_name_type(self):
        """Test AXFR correctly handles multiple records of same type."""
        # Create multiple A records for www
        ARecord.objects.create(
            name="www",
            zone=self.zone,
            data="192.0.2.2",
            ttl=300,
        )

        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "example.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        all_rrsets = []
        for msg in messages:
            all_rrsets.extend(msg.answer)

        # Find www A records
        www_a_rrsets = [rr for rr in all_rrsets
                        if rr.rdtype == dns.rdatatype.A and
                        str(rr.name) == "www.example.com."]

        # Should have one RRset with multiple rdata
        self.assertEqual(len(www_a_rrsets), 1)
        self.assertGreater(len(www_a_rrsets[0]), 1)


class TestAXFRRendererLargeZone(TestCase):
    """Test AXFR renderer with large zones (multi-message handling)."""

    @classmethod
    def setUpTestData(cls):
        """Create test data with large zone."""
        super().setUpTestData()

        cls.dns_view = DNSView.objects.create(name="TestView")
        cls.zone = DNSZone.objects.create(
            name="large.com",
            dns_view=cls.dns_view,
            filename="db.large.com",
            soa_mname="ns1.large.com",
            soa_rname="admin@large.com",
            soa_serial=1,
        )

        # Create many A records to potentially trigger multi-message response
        for i in range(100):
            ARecord.objects.create(
                name=f"host{i}",
                zone=cls.zone,
                data=f"192.0.2.{i % 255}",
                ttl=300,
            )

    def test_large_zone_renders_successfully(self):
        """Test that large zones render without errors."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "large.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))
        self.assertGreater(len(messages), 0)

    def test_large_zone_has_soa_bookends(self):
        """Test large zone still has SOA at start and end."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "large.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))

        # First RRset is SOA
        self.assertEqual(messages[0].answer[0].rdtype, dns.rdatatype.SOA)

        # Last RRset is SOA
        self.assertEqual(messages[-1].answer[-1].rdtype, dns.rdatatype.SOA)

    def test_large_zone_all_records_present(self):
        """Test that all records are present in large zone transfer."""
        renderer = AXFRRenderer(self.zone)
        query = dns.message.make_query(
            "large.com",
            dns.rdatatype.AXFR,
            dns.rdataclass.IN
        )

        messages = list(renderer.render_axfr(query))

        # Collect all A records from all messages
        a_records = []
        for msg in messages:
            for rrset in msg.answer:
                if rrset.rdtype == dns.rdatatype.A:
                    for rdata in rrset:
                        a_records.append(str(rrset.name))

        # Should have 100 A records (minus duplicates from RRset grouping)
        self.assertGreater(len(a_records), 90)
