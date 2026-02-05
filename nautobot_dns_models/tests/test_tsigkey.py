"""Test TSIGKey model."""

import base64

from django.core.exceptions import ValidationError
from nautobot.apps.testing import ModelTestCases

from nautobot_dns_models.models import DNSView, DNSZone, TSIGKey, TSIGAlgorithmChoices


class TestTSIGKey(ModelTestCases.BaseModelTestCase):
    """Test TSIGKey model."""

    model = TSIGKey

    @classmethod
    def setUpTestData(cls):
        """Create test data for TSIGKey Model."""
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

        # Create exactly 3 test objects (NTC requirement)
        cls.key1 = TSIGKey.objects.create(
            name="transfer-key-1.example.com",
            algorithm=TSIGAlgorithmChoices.HMAC_SHA256,
            secret=base64.b64encode(b"secret1" * 4).decode("ascii"),
            description="Test key 1",
            is_active=True,
        )
        cls.key2 = TSIGKey.objects.create(
            name="transfer-key-2.example.com",
            algorithm=TSIGAlgorithmChoices.HMAC_SHA384,
            secret=base64.b64encode(b"secret2" * 6).decode("ascii"),
            description="Test key 2",
            is_active=True,
        )
        cls.key3 = TSIGKey.objects.create(
            name="transfer-key-3.example.com",
            algorithm=TSIGAlgorithmChoices.HMAC_SHA512,
            secret=base64.b64encode(b"secret3" * 8).decode("ascii"),
            description="Test key 3",
            is_active=False,
        )

    def test_create_tsigkey_only_required(self):
        """Create TSIGKey with only required fields."""
        key = TSIGKey.objects.create(
            name="minimal-key.example.com",
            secret=base64.b64encode(b"test_secret").decode("ascii"),
        )
        self.assertEqual(key.name, "minimal-key.example.com")
        self.assertEqual(key.algorithm, TSIGAlgorithmChoices.HMAC_SHA256)  # default
        self.assertTrue(key.is_active)  # default
        self.assertEqual(key.description, "")
        self.assertIsNone(key.last_used)

    def test_create_tsigkey_all_fields(self):
        """Create TSIGKey with all fields."""
        secret = base64.b64encode(b"full_test_secret").decode("ascii")
        key = TSIGKey.objects.create(
            name="full-key.example.com",
            algorithm=TSIGAlgorithmChoices.HMAC_SHA512,
            secret=secret,
            description="Full test key",
            is_active=True,
        )
        key.zones.add(self.zone1)

        self.assertEqual(key.name, "full-key.example.com")
        self.assertEqual(key.algorithm, TSIGAlgorithmChoices.HMAC_SHA512)
        self.assertEqual(key.secret, secret)
        self.assertEqual(key.description, "Full test key")
        self.assertTrue(key.is_active)
        self.assertIn(self.zone1, key.zones.all())

    def test_tsigkey_str_representation(self):
        """Test __str__ method."""
        self.assertEqual(
            str(self.key1),
            "transfer-key-1.example.com (hmac-sha256)"
        )
        self.assertEqual(
            str(self.key2),
            "transfer-key-2.example.com (hmac-sha384)"
        )

    def test_get_absolute_url(self):
        """Test get_absolute_url method."""
        self.assertEqual(
            self.key1.get_absolute_url(),
            f"/plugins/dns/tsig-keys/{self.key1.pk}/"
        )

    def test_tsigkey_unique_name(self):
        """Test that TSIG key names must be unique."""
        with self.assertRaises(Exception):  # Django will raise IntegrityError
            TSIGKey.objects.create(
                name="transfer-key-1.example.com",  # Duplicate
                secret=base64.b64encode(b"different_secret").decode("ascii"),
            )

    def test_generate_key_hmac_sha256(self):
        """Test key generation with HMAC-SHA256."""
        key = TSIGKey.generate_key(
            name="generated-sha256.example.com",
            algorithm=TSIGAlgorithmChoices.HMAC_SHA256,
            description="Generated key"
        )
        self.assertEqual(key.name, "generated-sha256.example.com")
        self.assertEqual(key.algorithm, TSIGAlgorithmChoices.HMAC_SHA256)
        self.assertEqual(key.description, "Generated key")
        self.assertTrue(key.is_active)

        # Verify secret is valid base64
        decoded = base64.b64decode(key.secret)
        # HMAC-SHA256 should be 256 bits = 32 bytes
        self.assertEqual(len(decoded), 32)

    def test_generate_key_hmac_sha384(self):
        """Test key generation with HMAC-SHA384."""
        key = TSIGKey.generate_key(
            name="generated-sha384.example.com",
            algorithm=TSIGAlgorithmChoices.HMAC_SHA384
        )
        self.assertEqual(key.algorithm, TSIGAlgorithmChoices.HMAC_SHA384)

        # Verify secret length
        decoded = base64.b64decode(key.secret)
        # HMAC-SHA384 should be 384 bits = 48 bytes
        self.assertEqual(len(decoded), 48)

    def test_generate_key_hmac_sha512(self):
        """Test key generation with HMAC-SHA512."""
        key = TSIGKey.generate_key(
            name="generated-sha512.example.com",
            algorithm=TSIGAlgorithmChoices.HMAC_SHA512
        )
        self.assertEqual(key.algorithm, TSIGAlgorithmChoices.HMAC_SHA512)

        # Verify secret length
        decoded = base64.b64decode(key.secret)
        # HMAC-SHA512 should be 512 bits = 64 bytes
        self.assertEqual(len(decoded), 64)

    def test_generate_key_hmac_md5(self):
        """Test key generation with HMAC-MD5 (legacy)."""
        key = TSIGKey.generate_key(
            name="generated-md5.example.com",
            algorithm=TSIGAlgorithmChoices.HMAC_MD5
        )
        self.assertEqual(key.algorithm, TSIGAlgorithmChoices.HMAC_MD5)

        # Verify secret length
        decoded = base64.b64decode(key.secret)
        # HMAC-MD5 should be 128 bits = 16 bytes
        self.assertEqual(len(decoded), 16)

    def test_generate_key_unsaved(self):
        """Test that generate_key returns unsaved instance."""
        key = TSIGKey.generate_key("unsaved-key.example.com")
        self.assertIsNone(key.pk)  # Not saved yet

        # Should be able to save it
        key.save()
        self.assertIsNotNone(key.pk)

    def test_mark_used(self):
        """Test mark_used method updates last_used timestamp."""
        self.assertIsNone(self.key1.last_used)

        self.key1.mark_used()
        self.key1.refresh_from_db()

        self.assertIsNotNone(self.key1.last_used)

    def test_is_authorized_for_zone_global_key(self):
        """Test authorization for global key (no zones specified)."""
        # key1 has no zones assigned, so it's global
        self.assertTrue(self.key1.is_authorized_for_zone(self.zone1))
        self.assertTrue(self.key1.is_authorized_for_zone(self.zone2))

    def test_is_authorized_for_zone_specific_zone(self):
        """Test authorization for zone-specific key."""
        self.key2.zones.add(self.zone1)

        self.assertTrue(self.key2.is_authorized_for_zone(self.zone1))
        self.assertFalse(self.key2.is_authorized_for_zone(self.zone2))

    def test_is_authorized_for_zone_multiple_zones(self):
        """Test authorization for key with multiple zones."""
        key = TSIGKey.objects.create(
            name="multi-zone-key.example.com",
            secret=base64.b64encode(b"multi_secret").decode("ascii"),
        )
        key.zones.add(self.zone1, self.zone2)

        self.assertTrue(key.is_authorized_for_zone(self.zone1))
        self.assertTrue(key.is_authorized_for_zone(self.zone2))

    def test_is_authorized_for_zone_inactive_key(self):
        """Test that inactive keys are not authorized."""
        self.key3.zones.add(self.zone1)
        # key3 is inactive (is_active=False)
        self.assertFalse(self.key3.is_authorized_for_zone(self.zone1))

    def test_get_secret_display_full_length(self):
        """Test get_secret_display with normal length secret."""
        display = self.key1.get_secret_display()
        # Should show last 8 characters with asterisks
        self.assertTrue(display.startswith("*"))
        self.assertEqual(display[-8:], self.key1.secret[-8:])

    def test_get_secret_display_short_secret(self):
        """Test get_secret_display with short secret."""
        key = TSIGKey.objects.create(
            name="short-key.example.com",
            secret="short",  # Less than 8 chars
        )
        display = key.get_secret_display()
        # Should be all asterisks
        self.assertEqual(display, "*****")

    def test_get_secret_display_empty_secret(self):
        """Test get_secret_display with empty secret."""
        key = TSIGKey(name="empty-key.example.com", secret="")
        display = key.get_secret_display()
        self.assertEqual(display, "")

    def test_clean_valid_name(self):
        """Test validation accepts valid DNS names."""
        key = TSIGKey(
            name="valid-key.example.com",
            secret=base64.b64encode(b"valid_secret").decode("ascii"),
        )
        key.clean()  # Should not raise

    def test_clean_invalid_name_special_chars(self):
        """Test validation rejects invalid DNS names."""
        key = TSIGKey(
            name="invalid@key!.example.com",
            secret=base64.b64encode(b"test_secret").decode("ascii"),
        )
        with self.assertRaises(ValidationError) as context:
            key.clean()
        self.assertIn("name", context.exception.message_dict)

    def test_clean_invalid_name_label_too_long(self):
        """Test validation rejects DNS labels that are too long."""
        long_label = "a" * 64  # DNS labels max out at 63 chars
        key = TSIGKey(
            name=f"{long_label}.example.com",
            secret=base64.b64encode(b"test_secret").decode("ascii"),
        )
        with self.assertRaises(ValidationError) as context:
            key.clean()
        self.assertIn("name", context.exception.message_dict)

    def test_clean_valid_base64_secret(self):
        """Test validation accepts valid base64 secrets."""
        key = TSIGKey(
            name="test-key.example.com",
            secret=base64.b64encode(b"valid_secret").decode("ascii"),
        )
        key.clean()  # Should not raise

    def test_clean_invalid_base64_secret(self):
        """Test validation rejects invalid base64 secrets."""
        key = TSIGKey(
            name="test-key.example.com",
            secret="not-valid-base64!@#",
        )
        with self.assertRaises(ValidationError) as context:
            key.clean()
        self.assertIn("secret", context.exception.message_dict)

    def test_save_calls_clean(self):
        """Test that save() calls clean() for validation."""
        key = TSIGKey(
            name="invalid@name.com",
            secret=base64.b64encode(b"secret").decode("ascii"),
        )
        with self.assertRaises(ValidationError):
            key.save()

    def test_algorithm_choices(self):
        """Test all algorithm choices are valid."""
        for algorithm in [
            TSIGAlgorithmChoices.HMAC_SHA256,
            TSIGAlgorithmChoices.HMAC_SHA384,
            TSIGAlgorithmChoices.HMAC_SHA512,
            TSIGAlgorithmChoices.HMAC_MD5,
        ]:
            key = TSIGKey.objects.create(
                name=f"algo-test-{algorithm}.example.com",
                algorithm=algorithm,
                secret=base64.b64encode(b"test_secret").decode("ascii"),
            )
            self.assertEqual(key.algorithm, algorithm)

    def test_zones_many_to_many(self):
        """Test zones ManyToMany relationship."""
        key = TSIGKey.objects.create(
            name="m2m-test-key.example.com",
            secret=base64.b64encode(b"test_secret").decode("ascii"),
        )

        # Add zones
        key.zones.add(self.zone1, self.zone2)
        self.assertEqual(key.zones.count(), 2)
        self.assertIn(self.zone1, key.zones.all())
        self.assertIn(self.zone2, key.zones.all())

        # Remove a zone
        key.zones.remove(self.zone1)
        self.assertEqual(key.zones.count(), 1)
        self.assertNotIn(self.zone1, key.zones.all())

    def test_reverse_relationship_from_zone(self):
        """Test reverse relationship from DNSZone to TSIGKey."""
        self.key1.zones.add(self.zone1)

        # Access keys from zone
        keys = self.zone1.tsig_keys.all()
        self.assertIn(self.key1, keys)

    def test_different_algorithms_produce_different_secrets(self):
        """Test that generated keys with different algorithms have different secrets."""
        key256 = TSIGKey.generate_key("test256.example.com", TSIGAlgorithmChoices.HMAC_SHA256)
        key384 = TSIGKey.generate_key("test384.example.com", TSIGAlgorithmChoices.HMAC_SHA384)
        key512 = TSIGKey.generate_key("test512.example.com", TSIGAlgorithmChoices.HMAC_SHA512)

        # Different lengths
        self.assertNotEqual(len(key256.secret), len(key384.secret))
        self.assertNotEqual(len(key384.secret), len(key512.secret))
        self.assertNotEqual(len(key256.secret), len(key512.secret))

        # Different values (statistically should never collide)
        self.assertNotEqual(key256.secret, key384.secret)
        self.assertNotEqual(key384.secret, key512.secret)

    def test_multiple_keys_can_have_same_zones(self):
        """Test that multiple keys can be authorized for the same zones."""
        key_a = TSIGKey.objects.create(
            name="key-a.example.com",
            secret=base64.b64encode(b"secret_a").decode("ascii"),
        )
        key_b = TSIGKey.objects.create(
            name="key-b.example.com",
            secret=base64.b64encode(b"secret_b").decode("ascii"),
        )

        key_a.zones.add(self.zone1)
        key_b.zones.add(self.zone1)

        self.assertTrue(key_a.is_authorized_for_zone(self.zone1))
        self.assertTrue(key_b.is_authorized_for_zone(self.zone1))

        zone_keys = self.zone1.tsig_keys.all()
        self.assertIn(key_a, zone_keys)
        self.assertIn(key_b, zone_keys)
