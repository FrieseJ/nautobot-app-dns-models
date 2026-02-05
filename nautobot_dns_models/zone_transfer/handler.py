"""Request handler for zone transfer requests.

Implements the 3-stage validation pipeline:
1. ACL check (IP-based access control)
2. TSIG validation (cryptographic signature)
3. Query type check (AXFR/IXFR only)
"""

import logging
from typing import Iterator, Optional

import dns.message
import dns.rcode
import dns.opcode
import dns.rdatatype

from .validators import acl_check, tsig_validate
from .renderer import AXFRRenderer

logger = logging.getLogger(__name__)


class ZoneTransferHandler:
    """Handles DNS zone transfer requests with 3-stage validation."""

    def __init__(self, source_ip: str, source_port: int):
        """Initialize handler for a specific client.

        Args:
            source_ip: IP address of the requesting client
            source_port: Source port of the request
        """
        self.source_ip = source_ip
        self.source_port = source_port

    def handle_request(self, request_data: bytes) -> Iterator[bytes]:
        """Process a zone transfer request and generate response.

        Implements 3-stage validation pipeline per project requirements:
        1. ACL check - IP-based access control
        2. TSIG validation - Cryptographic signature verification
        3. Query type check - Only AXFR (type 252) initially

        Args:
            request_data: Raw DNS message bytes

        Yields:
            DNS response message bytes (may be multiple messages for AXFR)
        """
        # Parse the DNS message
        try:
            query = dns.message.from_wire(request_data)
        except Exception as e:
            logger.warning(f"Failed to parse DNS message from {self.source_ip}: {e}")
            # Return FORMERR for malformed queries
            yield self._build_error_response(dns.rcode.FORMERR).to_wire()
            return

        # Validate message structure
        if not query.question:
            logger.warning(f"Query from {self.source_ip} has no question section")
            yield self._build_error_response(dns.rcode.FORMERR, query).to_wire()
            return

        question = query.question[0]
        qname = str(question.name).rstrip('.')
        qtype = question.rdtype

        logger.info(f"Zone transfer request from {self.source_ip}:{self.source_port} for {qname} type {qtype}")

        # Stage 3: Query type check (check early to avoid expensive lookups for non-AXFR)
        if qtype not in (dns.rdatatype.AXFR, dns.rdatatype.IXFR):
            logger.info(f"Rejecting non-AXFR/IXFR query from {self.source_ip} (type {qtype})")
            # Return REFUSED or NOTIMP for non-zone-transfer queries
            yield self._build_error_response(dns.rcode.REFUSED, query).to_wire()
            return

        if qtype == dns.rdatatype.IXFR:
            logger.info(f"IXFR not yet implemented, rejecting query from {self.source_ip}")
            yield self._build_error_response(dns.rcode.NOTIMP, query).to_wire()
            return

        # Look up the zone
        zone = self._find_zone(qname)
        if not zone:
            logger.info(f"Zone {qname} not found for request from {self.source_ip}")
            yield self._build_error_response(dns.rcode.REFUSED, query).to_wire()
            return

        # Stage 1: ACL Check
        if not acl_check(self.source_ip, zone):
            logger.warning(f"ACL check failed for {self.source_ip} on zone {qname}")
            yield self._build_error_response(dns.rcode.REFUSED, query).to_wire()
            return

        # Stage 2: TSIG Validation (if TSIG present)
        if query.tsig:
            is_valid, error_code = tsig_validate(query, zone)
            if not is_valid:
                logger.warning(f"TSIG validation failed for {self.source_ip} on zone {qname}: {error_code}")
                # Return appropriate TSIG error
                yield self._build_tsig_error_response(query, error_code).to_wire()
                return
        else:
            # No TSIG in request - check if zone requires TSIG
            if self._zone_requires_tsig(zone):
                logger.warning(f"Zone {qname} requires TSIG but none provided by {self.source_ip}")
                yield self._build_error_response(dns.rcode.REFUSED, query).to_wire()
                return

        # All validation passed - generate AXFR response
        logger.info(f"Validation passed, generating AXFR for zone {qname} to {self.source_ip}")
        renderer = AXFRRenderer(zone)

        try:
            for response_message in renderer.render_axfr(query):
                yield response_message.to_wire()
        except Exception as e:
            logger.error(f"Error generating AXFR for zone {qname}: {e}", exc_info=True)
            yield self._build_error_response(dns.rcode.SERVFAIL, query).to_wire()

    def _find_zone(self, zone_name: str):
        """Look up a DNSZone by name.

        Args:
            zone_name: Fully qualified zone name

        Returns:
            DNSZone instance or None if not found
        """
        # Import here to avoid circular imports
        from nautobot_dns_models.models import DNSZone

        try:
            # Try exact match first
            return DNSZone.objects.get(name=zone_name)
        except DNSZone.DoesNotExist:
            # Try with trailing dot removed
            if zone_name.endswith('.'):
                try:
                    return DNSZone.objects.get(name=zone_name.rstrip('.'))
                except DNSZone.DoesNotExist:
                    pass
            return None
        except DNSZone.MultipleObjectsReturned:
            logger.error(f"Multiple zones found for name {zone_name}")
            return None

    def _zone_requires_tsig(self, zone) -> bool:
        """Check if a zone requires TSIG authentication.

        Args:
            zone: DNSZone instance

        Returns:
            True if TSIG is required, False otherwise
        """
        # Import here to avoid circular imports
        try:
            from nautobot_dns_models.models import TSIGKey
            from django.db import models
            # Check if there are any TSIG keys associated with this zone
            # Keys can be global (no zones) or zone-specific (zones contains this zone)
            return TSIGKey.objects.filter(
                models.Q(zones__isnull=True) | models.Q(zones=zone),
                is_active=True
            ).exists()
        except ImportError:
            return False

    def _build_error_response(
        self,
        rcode: int,
        query: Optional[dns.message.Message] = None
    ) -> dns.message.Message:
        """Build a DNS error response.

        Args:
            rcode: DNS response code (REFUSED, FORMERR, SERVFAIL, etc.)
            query: Original query message (optional)

        Returns:
            dns.message.Message with error rcode
        """
        if query:
            response = dns.message.make_response(query)
        else:
            response = dns.message.Message()

        response.set_rcode(rcode)
        return response

    def _build_tsig_error_response(
        self,
        query: dns.message.Message,
        error_code: str
    ) -> dns.message.Message:
        """Build a TSIG error response.

        Args:
            query: Original query message with TSIG
            error_code: TSIG error code (BADKEY, BADSIG, BADTIME, NOTAUTH)

        Returns:
            dns.message.Message with TSIG error
        """
        response = dns.message.make_response(query)

        # Map error codes to DNS rcodes
        error_map = {
            'BADKEY': dns.rcode.BADKEY,
            'BADSIG': dns.rcode.BADSIG,
            'BADTIME': dns.rcode.BADTIME,
            'NOTAUTH': dns.rcode.NOTAUTH,
        }

        rcode = error_map.get(error_code, dns.rcode.NOTAUTH)
        response.set_rcode(rcode)

        return response
