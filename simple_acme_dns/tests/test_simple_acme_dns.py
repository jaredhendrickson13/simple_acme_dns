# Copyright 2025 Jared Hendrickson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests primary functionality of the simple_acme_dns package."""
import os
import random
import time
import unittest

import acme.messages

import simple_acme_dns
from simple_acme_dns.tests.tools import (
    GoogleDNSClient,
    is_csr,
    is_cert,
    is_json,
    is_private_key,
)

# Variables and constants
BASE_DOMAIN = "testing.jaredhendrickson.com"
TEST_DOMAINS = [f"{random.randint(10000, 99999)}.simple-acme-dns.{BASE_DOMAIN}"]
TEST_EMAIL = f"simple-acme-dns@{BASE_DOMAIN}"
TEST_DIRECTORY = os.environ.get(
    "ACME_DIRECTORY", "https://acme-staging-v02.api.letsencrypt.org/directory"
)
TEST_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]
unittest.TestLoader.sortTestMethodsUsing = None  # Ensure tests run in order


class TestSimpleAcmeDns(unittest.TestCase):
    """Tests the simple_acme_dns module."""

    # Shared attributes
    client = None

    @classmethod
    def setUpClass(cls):
        """Creates shared objects for each test to use."""
        cls.client = simple_acme_dns.ACMEClient(
            domains=TEST_DOMAINS,
            email=TEST_EMAIL,
            directory=TEST_DIRECTORY,
            nameservers=TEST_NAMESERVERS,
            verify_ssl=False,
        )

    @classmethod
    def tearDownClass(cls):
        """Deactivate accounts on teardown"""
        # Remove any DNS records created
        for domain, _ in cls.client.verification_tokens.items():
            try:
                gcloud_dns = GoogleDNSClient(name=domain, rtype="TXT", ttl=360, data="")
                gcloud_dns.delete_record()
            except ValueError:
                pass

        # Deactivate the created ACME account
        try:
            cls.client.deactivate_account(delete=True)
        except (simple_acme_dns.errors.InvalidAccount, acme.messages.Error):
            pass

    def test_generate_keys_and_csr(self):
        """Test to ensure both keys and CSRs are generated correctly."""
        # Variables
        key_type_options = ["ec256", "ec384", "rsa2048", "rsa4096"]

        # Ensure each key option is accepted and generates the correct key format
        for key_type in key_type_options:
            self.assertIsInstance(
                self.client.generate_private_key(key_type=key_type), bytes
            )
            self.assertTrue(is_private_key(self.client.private_key, key_type))

        # Ensure the CSR is generated correctly
        self.assertTrue(is_csr(self.client.generate_csr()))

    def test_account_enrollment(self):
        """Test to ensure ACME accounts are successfully registered."""
        self.client.new_account(verify_ssl=False)
        self.assertIsNotNone(self.client.account)
        self.assertIsNotNone(self.client.account_key)
        self.assertTrue(is_json(self.client.export_account()))

    def test_shorthand_enrollment_and_csr(self):
        """Checks that both the account enrollment and CSR can be done at object initialization."""
        client = simple_acme_dns.ACMEClient(
            domains=TEST_DOMAINS,
            email=TEST_EMAIL,
            directory=TEST_DIRECTORY,
            nameservers=TEST_NAMESERVERS,
            new_account=True,
            generate_csr=True,
            verify_ssl=False,
        )

        # Ensure there is an account enrolled and a CSR/private key created
        self.assertIsNotNone(client.account)
        self.assertIsNotNone(client.account_key)
        self.assertIsInstance(client.private_key, bytes)
        self.assertIsInstance(client.csr, bytes)

        # Deactivate this test account
        client.deactivate_account()

    def test_private_key_type_options(self):
        """Test to ensure only listed ACME key types are supported"""
        with self.assertRaises(simple_acme_dns.errors.InvalidKeyType):
            self.client.generate_private_key("INVALID")

    def test_acme_verification_and_cert(self):
        """Test to ensure ACME verification works and a certificate is obtained."""
        # Request verification tokens
        self.client.generate_private_key_and_csr()
        self.client.new_account(verify_ssl=False)
        self.assertIsInstance(self.client.request_verification_tokens(), dict)

        # Before we actually create the DNS entries, ensure DNS propagation checks fail as expected
        self.assertFalse(self.client.check_dns_propagation(timeout=5, interval=1))

        # Create the TXT record to verify ACME verification for each domain
        for domain, tokens in self.client.verification_tokens.items():
            gcloud_dns = GoogleDNSClient(
                name=domain, rtype="TXT", ttl=3600, data=tokens
            )
            gcloud_dns.create_record(replace=True)

        # Start ACME verification and ensure DNS propagation checks work
        self.assertTrue(
            # Check via round robin
            self.client.check_dns_propagation(round_robin=True)
        )
        self.assertTrue(
            # Check via authoritative nameserver
            self.client.check_dns_propagation(authoritative=True, verbose=True)
        )

        # Request the certificates and ensure a certificate is received
        time.sleep(15)  # Wait for DNS to propagate
        self.assertTrue(is_cert(self.client.request_certificate()))

    def test_account_exports(self):
        """Checks that the account can be exported as a JSON string or file."""
        # Run export methods
        self.assertTrue(is_json(self.client.export_account(save_private_key=True)))
        self.client.export_account_to_file(
            name="_test-account.json", save_private_key=True
        )

        # Ensure the export file is written
        self.assertTrue(os.path.exists("./_test-account.json"))

    def test_account_export_directory_exists_constraint(self):
        """Ensures file-based account exports can only be done to a directory that exists."""
        with self.assertRaises(simple_acme_dns.errors.InvalidPath):
            self.client.export_account_to_file(path="/INVALID_PATH")

    def test_account_imports(self):
        """Checks that account exports can be imported."""
        # Ensure the account can be imported via JSON string and that it matches the original object
        json_str_import = simple_acme_dns.ACMEClient.load_account(
            self.client.export_account(save_private_key=True)
        )
        self.assertEqual(
            self.client.export_account(save_private_key=True),
            json_str_import.export_account(save_private_key=True),
        )

        # Ensure the account can be imported via JSON file exported previously and that it matches the original object
        json_file_import = simple_acme_dns.ACMEClient.load_account_from_file(
            "./_test-account.json"
        )
        self.assertEqual(
            self.client.export_account(save_private_key=True),
            json_file_import.export_account(save_private_key=True),
        )

    def test_account_import_files(self):
        """Ensure filed-based account imports reference an existing file."""
        with self.assertRaises(simple_acme_dns.errors.InvalidPath):
            self.client.load_account_from_file("/tmp/INVALID.json")

    def test_revoke_certificate(self):
        """Ensure we can revoke the certificate successfully."""
        # Revoke the certificate
        self.assertIsNone(self.client.revoke_certificate())

    def test_delete_account_file(self):
        """Ensure we can delete associated account files."""
        # Enroll a new account without saving it and ensure it can be 'deleted' without raising an error
        client = simple_acme_dns.ACMEClient(
            domains=TEST_DOMAINS,
            email=TEST_EMAIL,
            directory=TEST_DIRECTORY,
            nameservers=TEST_NAMESERVERS,
            new_account=True,
            generate_csr=True,
            verify_ssl=False,
        )
        client.account_path = "INVALID_FILE.json"
        self.assertIsNone(client.deactivate_account(delete=True))

    def test_email_property_when_email_is_set(self):
        """Checks that the email property is set correctly."""
        self.client.email = "test@example.com"
        self.assertEqual(self.client.email, "test@example.com")

    def test_email_property_when_email_is_not_set(self):
        """Checks that the email property raises an error when not set."""
        with self.assertRaises(simple_acme_dns.errors.InvalidEmail):
            client = simple_acme_dns.ACMEClient(
                domains=TEST_DOMAINS,
                directory=TEST_DIRECTORY,
                nameservers=TEST_NAMESERVERS,
                verify_ssl=False,
            )
            client.email = "not an email"


if __name__ == "__main__":
    unittest.main()
