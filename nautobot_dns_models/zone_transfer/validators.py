"""Validation logic for zone transfer requests.

Provides ACL (IP-based access control) and TSIG (transaction signature) validation
per RFC 2845 and RFC 5936.
"""

import base64
import logging
import os
from typing import Optional, Tuple
import ipaddress

import dns.tsig
import dns.message

logger = logging.getLogger(__name__)


def acl_check(source_ip: str, zone) -> bool:
    """Check if source IP is allowed to perform zone transfer for the given zone.

    Args:
        source_ip: IP address of the requesting client (string format)
        zone: DNSZone model instance

    Returns:
        True if the source IP is allowed, False otherwise

    Stage 1 of the validation pipeline per project requirements.
    """
    try:
        source_addr = ipaddress.ip_address(source_ip)
    except ValueError:
        logger.warning(f"Invalid source IP format: {source_ip}")
        return False

    # Import here to avoid circular imports
    try:
        from nautobot_dns_models.models import ZoneTransferACL
    except ImportError:
        logger.error("ZoneTransferACL model not found. ACL checking disabled.")
        return False

    # Use the ZoneTransferACL.check_access() class method for proper evaluation
    allowed, matched_acl, reason = ZoneTransferACL.check_access(
        client_ip=source_ip,
        zone=zone,
        tsig_key=None
    )

    if allowed:
        logger.info(f"ACL check passed: {reason}")
    else:
        logger.info(f"ACL check failed: {reason}")

    return allowed


def tsig_validate(dns_message: dns.message.Message, zone) -> Tuple[bool, Optional[str]]:
    """Validate TSIG signature on a DNS message with constant-time properties.

    Uses always-compute-HMAC pattern to prevent timing-based key enumeration.
    Even when a key doesn't exist, HMAC computation is performed using a dummy key
    to maintain consistent timing across all code paths.

    Args:
        dns_message: dns.message.Message instance with potential TSIG
        zone: DNSZone model instance

    Returns:
        Tuple of (is_valid: bool, error_code: Optional[str])
        error_code will be one of: 'BADKEY', 'BADSIG', 'BADTIME', 'NOTAUTH', or None if valid

    Stage 2 of the validation pipeline per project requirements.
    Supports HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 per RFC 8945.
    """
    # Import here to avoid circular imports
    try:
        from nautobot_dns_models.models import TSIGKey
        from constance import config as constance_config
    except ImportError:
        logger.error("TSIGKey model not found. TSIG validation disabled.")
        return (False, 'NOTAUTH')

    # Check if message has TSIG
    if not dns_message.tsig:
        logger.info(f"No TSIG in message for zone {zone.name}")
        return (False, 'NOTAUTH')

    # Extract TSIG key name
    tsig_key_name = str(dns_message.keyname)
    logger.debug(f"TSIG key name from message: {tsig_key_name}")

    # Check if constant-time validation is enabled
    constant_time = getattr(constance_config, 'ZONE_TRANSFER_CONSTANT_TIME_VALIDATION', True)

    # Create dummy key for constant-time operation (used when real key doesn't exist)
    dummy_key_data = {
        'name': '__dummy__',
        'secret': base64.b64encode(os.urandom(32)).decode('ascii'),
        'algorithm': dns.tsig.HMAC_SHA256,
        'zone': None,
        'enabled': False,
    }

    # Look up the TSIG key in database
    use_real_key = False
    key_not_authorized = False
    tsig_key_dict = dummy_key_data.copy()  # Start with dummy

    try:
        real_tsig_key = TSIGKey.objects.get(
            name=tsig_key_name,
            is_active=True
        )
        use_real_key = True

        # Check if this key is authorized for this zone using the model method
        if not real_tsig_key.is_authorized_for_zone(zone):
            key_not_authorized = True
            if not constant_time:
                # Fast path: return immediately if not constant-time
                logger.warning(f"TSIG key {tsig_key_name} not authorized for zone {zone.name}")
                return (False, 'NOTAUTH')

        # Use real key data for validation
        tsig_key_dict = {
            'name': real_tsig_key.name,
            'secret': real_tsig_key.secret,
            'algorithm': real_tsig_key.algorithm,
            'zone': real_tsig_key.zone,
            'enabled': real_tsig_key.enabled,
        }

    except TSIGKey.DoesNotExist:
        logger.warning(f"TSIG key {tsig_key_name} not found in database")
        if not constant_time:
            # Fast path: return immediately if not constant-time
            return (False, 'BADKEY')
        # Otherwise fall through to HMAC computation with dummy key

    except TSIGKey.MultipleObjectsReturned:
        logger.error(f"Multiple TSIG keys found for name {tsig_key_name}")
        if not constant_time:
            return (False, 'BADKEY')

    # ALWAYS compute HMAC (even if key doesn't exist or not authorized)
    # This is the core of constant-time validation
    keyring = dns.tsig.Key(
        name=tsig_key_dict['name'],
        secret=tsig_key_dict['secret'],
        algorithm=tsig_key_dict['algorithm']
    )

    signature_valid = False
    tsig_error = None

    try:
        # Validate the TSIG using dnspython
        # This checks signature validity and time window
        dns_message.tsig_verify(keyring)
        signature_valid = True

    except dns.tsig.BadSignature:
        tsig_error = 'BADSIG'
    except dns.tsig.BadTime:
        tsig_error = 'BADTIME'
    except Exception as e:
        logger.debug(f"TSIG validation exception: {e}")
        tsig_error = 'NOTAUTH'

    # Now return appropriate error based on actual state
    # Priority order: key existence > authorization > signature validity

    if not use_real_key:
        # Key doesn't exist - BADKEY takes priority
        return (False, 'BADKEY')

    if key_not_authorized:
        # Key exists but not authorized for this zone
        logger.warning(f"TSIG key {tsig_key_name} not authorized for zone {zone.name}")
        return (False, 'NOTAUTH')

    if not signature_valid:
        # Key exists and authorized, but signature invalid
        logger.warning(f"TSIG {tsig_error} for key {tsig_key_name}")
        return (False, tsig_error)

    # All checks passed
    logger.info(f"TSIG validation successful for key {tsig_key_name} on zone {zone.name}")
    return (True, None)
