"""AXFR response renderer for DNS zone transfers.

Generates RFC 5936-compliant AXFR responses from Nautobot DNSZone data.
"""

import logging
from io import BytesIO
from typing import List, Iterator

import dns.message
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rdata

logger = logging.getLogger(__name__)


class AXFRRenderer:
    """Renders DNS zone data as AXFR response messages."""

    # Maximum message size before splitting into multiple messages
    MAX_MESSAGE_SIZE = 65535

    def __init__(self, zone):
        """Initialize renderer for a specific zone.

        Args:
            zone: DNSZone model instance
        """
        self.zone = zone
        # Ensure zone name is absolute (has trailing dot) for wire format
        zone_name_str = zone.name if zone.name.endswith('.') else f"{zone.name}."
        self.zone_name = dns.name.from_text(zone_name_str)

    def render_axfr(self, query_message: dns.message.Message) -> Iterator[dns.message.Message]:
        """Generate AXFR response messages for the zone.

        Per RFC 5936, AXFR response:
        - Starts with SOA record
        - Contains all RRsets in the zone
        - Ends with SOA record (same as start)
        - May span multiple DNS messages

        Args:
            query_message: Original query message (for ID, TSIG context)

        Yields:
            dns.message.Message instances containing zone data
        """
        # Import record models here to avoid circular imports
        from nautobot_dns_models.models import (
            NSRecord,
            ARecord,
            AAAARecord,
            CNAMERecord,
            MXRecord,
            TXTRecord,
            PTRRecord,
            SRVRecord,
        )

        logger.info(f"Rendering AXFR for zone {self.zone.name} (serial {self.zone.soa_serial})")

        # Start first message
        response = self._create_response_message(query_message)
        rrsets_added = 0

        # Add SOA record at the beginning (RFC 5936 §2.2)
        soa_rrset = self._build_soa_rrset()
        response.answer.append(soa_rrset)
        rrsets_added += 1

        # Build all RRsets for the zone
        all_rrsets = []

        # NS Records
        all_rrsets.extend(self._build_ns_rrsets(NSRecord))

        # A Records
        all_rrsets.extend(self._build_a_rrsets(ARecord))

        # AAAA Records
        all_rrsets.extend(self._build_aaaa_rrsets(AAAARecord))

        # CNAME Records
        all_rrsets.extend(self._build_cname_rrsets(CNAMERecord))

        # MX Records
        all_rrsets.extend(self._build_mx_rrsets(MXRecord))

        # TXT Records
        all_rrsets.extend(self._build_txt_rrsets(TXTRecord))

        # PTR Records
        all_rrsets.extend(self._build_ptr_rrsets(PTRRecord))

        # SRV Records
        all_rrsets.extend(self._build_srv_rrsets(SRVRecord))

        logger.debug(f"Built {len(all_rrsets)} RRsets for zone {self.zone.name}")

        # Add RRsets to response, splitting into multiple messages if needed
        for rrset in all_rrsets:
            # Check if adding this RRset would exceed message size
            # Use BytesIO to get wire format length
            rrset_wire = BytesIO()
            rrset.to_wire(rrset_wire)
            rrset_size = len(rrset_wire.getvalue())

            if len(response.to_wire()) + rrset_size > self.MAX_MESSAGE_SIZE:
                # Yield current message and start a new one
                logger.debug(f"Message size limit reached, yielding message with {rrsets_added} RRsets")
                yield response
                response = self._create_response_message(query_message)
                rrsets_added = 0

            response.answer.append(rrset)
            rrsets_added += 1

        # Add SOA record at the end (RFC 5936 §2.2)
        response.answer.append(soa_rrset)
        rrsets_added += 1

        logger.info(f"AXFR complete for zone {self.zone.name}, final message has {rrsets_added} RRsets")
        yield response

    def _create_response_message(self, query_message: dns.message.Message) -> dns.message.Message:
        """Create a DNS response message for AXFR.

        Args:
            query_message: Original query message

        Returns:
            dns.message.Message configured as AXFR response
        """
        response = dns.message.make_response(query_message)
        response.flags |= dns.flags.AA  # Authoritative Answer
        return response

    def _build_soa_rrset(self) -> dns.rrset.RRset:
        """Build SOA RRset from zone data."""
        rrset = dns.rrset.RRset(self.zone_name, dns.rdataclass.IN, dns.rdatatype.SOA)
        rrset.ttl = self.zone.ttl

        # Ensure mname and rname are absolute (have trailing dots)
        mname = self.zone.soa_mname if self.zone.soa_mname.endswith('.') else f"{self.zone.soa_mname}."
        rname = self._email_to_rname(self.zone.soa_rname)
        if not rname.endswith('.'):
            rname += '.'

        soa_rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            f"{mname} {rname} "
            f"{self.zone.soa_serial} {self.zone.soa_refresh} {self.zone.soa_retry} "
            f"{self.zone.soa_expire} {self.zone.soa_minimum}"
        )
        rrset.add(soa_rdata)
        return rrset

    def _build_ns_rrsets(self, NSRecord) -> List[dns.rrset.RRset]:
        """Build NS RRsets from NSRecord model."""
        rrsets = {}
        for ns_record in NSRecord.objects.filter(zone=self.zone):
            record_name = self._build_record_name(ns_record.name)
            key = (record_name, ns_record.ttl)

            if key not in rrsets:
                rrsets[key] = dns.rrset.RRset(record_name, dns.rdataclass.IN, dns.rdatatype.NS)
                rrsets[key].ttl = ns_record.ttl

            # Ensure server name is absolute
            server = ns_record.server if ns_record.server.endswith('.') else f"{ns_record.server}."
            rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, server)
            rrsets[key].add(rdata)

        return list(rrsets.values())

    def _build_a_rrsets(self, ARecord) -> List[dns.rrset.RRset]:
        """Build A RRsets from ARecord model."""
        rrsets = {}
        for a_record in ARecord.objects.filter(zone=self.zone).select_related('ip_address'):
            record_name = self._build_record_name(a_record.name)
            key = (record_name, a_record.ttl)

            if key not in rrsets:
                rrsets[key] = dns.rrset.RRset(record_name, dns.rdataclass.IN, dns.rdatatype.A)
                rrsets[key].ttl = a_record.ttl

            rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.A,
                str(a_record.ip_address.address.ip)
            )
            rrsets[key].add(rdata)

        return list(rrsets.values())

    def _build_aaaa_rrsets(self, AAAARecord) -> List[dns.rrset.RRset]:
        """Build AAAA RRsets from AAAARecord model."""
        rrsets = {}
        for aaaa_record in AAAARecord.objects.filter(zone=self.zone).select_related('ip_address'):
            record_name = self._build_record_name(aaaa_record.name)
            key = (record_name, aaaa_record.ttl)

            if key not in rrsets:
                rrsets[key] = dns.rrset.RRset(record_name, dns.rdataclass.IN, dns.rdatatype.AAAA)
                rrsets[key].ttl = aaaa_record.ttl

            rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.AAAA,
                str(aaaa_record.ip_address.address.ip)
            )
            rrsets[key].add(rdata)

        return list(rrsets.values())

    def _build_cname_rrsets(self, CNAMERecord) -> List[dns.rrset.RRset]:
        """Build CNAME RRsets from CNAMERecord model."""
        rrsets = []
        for cname_record in CNAMERecord.objects.filter(zone=self.zone):
            record_name = self._build_record_name(cname_record.name)
            rrset = dns.rrset.RRset(record_name, dns.rdataclass.IN, dns.rdatatype.CNAME)
            rrset.ttl = cname_record.ttl

            # Ensure alias is absolute
            alias = cname_record.alias if cname_record.alias.endswith('.') else f"{cname_record.alias}."
            rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CNAME, alias)
            rrset.add(rdata)
            rrsets.append(rrset)

        return rrsets

    def _build_mx_rrsets(self, MXRecord) -> List[dns.rrset.RRset]:
        """Build MX RRsets from MXRecord model."""
        rrsets = {}
        for mx_record in MXRecord.objects.filter(zone=self.zone):
            record_name = self._build_record_name(mx_record.name)
            key = (record_name, mx_record.ttl)

            if key not in rrsets:
                rrsets[key] = dns.rrset.RRset(record_name, dns.rdataclass.IN, dns.rdatatype.MX)
                rrsets[key].ttl = mx_record.ttl

            # Ensure mail server is absolute
            mail_server = mx_record.mail_server if mx_record.mail_server.endswith('.') else f"{mx_record.mail_server}."
            rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.MX,
                f"{mx_record.preference} {mail_server}"
            )
            rrsets[key].add(rdata)

        return list(rrsets.values())

    def _build_txt_rrsets(self, TXTRecord) -> List[dns.rrset.RRset]:
        """Build TXT RRsets from TXTRecord model."""
        rrsets = {}
        for txt_record in TXTRecord.objects.filter(zone=self.zone):
            record_name = self._build_record_name(txt_record.name)
            key = (record_name, txt_record.ttl)

            if key not in rrsets:
                rrsets[key] = dns.rrset.RRset(record_name, dns.rdataclass.IN, dns.rdatatype.TXT)
                rrsets[key].ttl = txt_record.ttl

            # Escape quotes in text for proper DNS format
            text = txt_record.text.replace('"', '\\"')
            rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, f'"{text}"')
            rrsets[key].add(rdata)

        return list(rrsets.values())

    def _build_ptr_rrsets(self, PTRRecord) -> List[dns.rrset.RRset]:
        """Build PTR RRsets from PTRRecord model."""
        rrsets = []
        for ptr_record in PTRRecord.objects.filter(zone=self.zone):
            record_name = self._build_record_name(ptr_record.name)
            rrset = dns.rrset.RRset(record_name, dns.rdataclass.IN, dns.rdatatype.PTR)
            rrset.ttl = ptr_record.ttl

            # Ensure PTR target is absolute
            ptrdname = ptr_record.ptrdname if ptr_record.ptrdname.endswith('.') else f"{ptr_record.ptrdname}."
            rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.PTR, ptrdname)
            rrset.add(rdata)
            rrsets.append(rrset)

        return rrsets

    def _build_srv_rrsets(self, SRVRecord) -> List[dns.rrset.RRset]:
        """Build SRV RRsets from SRVRecord model."""
        rrsets = {}
        for srv_record in SRVRecord.objects.filter(zone=self.zone):
            record_name = self._build_record_name(srv_record.name)
            key = (record_name, srv_record.ttl)

            if key not in rrsets:
                rrsets[key] = dns.rrset.RRset(record_name, dns.rdataclass.IN, dns.rdatatype.SRV)
                rrsets[key].ttl = srv_record.ttl

            # Ensure SRV target is absolute
            target = srv_record.target if srv_record.target.endswith('.') else f"{srv_record.target}."
            rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.SRV,
                f"{srv_record.priority} {srv_record.weight} {srv_record.port} {target}"
            )
            rrsets[key].add(rdata)

        return list(rrsets.values())

    def _build_record_name(self, record_name: str) -> dns.name.Name:
        """Build a fully qualified domain name for a record.

        Args:
            record_name: Name from the record (may be empty for zone apex, or relative)

        Returns:
            dns.name.Name instance (absolute)
        """
        if not record_name or record_name == "@":
            # Zone apex
            return self.zone_name

        # Build FQDN: record.zone (ensure absolute with trailing dot)
        fqdn = f"{record_name}.{self.zone.name}"
        if not fqdn.endswith('.'):
            fqdn += '.'
        return dns.name.from_text(fqdn)

    @staticmethod
    def _email_to_rname(email: str) -> str:
        """Convert email address to DNS RNAME format.

        Converts user@example.com to user.example.com per RFC 1035.

        Args:
            email: Email address

        Returns:
            RNAME format string
        """
        # Replace first @ with .
        return email.replace('@', '.', 1)
