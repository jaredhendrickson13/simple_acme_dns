# Copyright 2023 Jared Hendrickson
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
"""Test error functionality with the simple_acme_dns package."""
import unittest

import simple_acme_dns


class MockOrder:
    """Creates a mock ACME Order object to use in testing."""
    # Supress pylint errors, this mock object only contains what is necessary for testing.
    # pylint: disable=too-few-public-methods
    authorizations = []


class TestSimpleAcmeDnsErrors(unittest.TestCase):
    """Checks to ensure exception classes used by simple_acme_dns are raised when expected."""
    def test_challenge_verification(self):
        """Checks that verification of available challenges is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()
        client.__order__ = MockOrder()

        # Ensure an error is thrown if there are no available challenges
        self.assertRaises(simple_acme_dns.errors.ChallengeUnavailable, client.__verify_challenge__)

    def test_registration_validation(self):
        """Checks that validation of registration is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure registration validation fails
        self.assertRaises(simple_acme_dns.errors.InvalidAccount, client.__validate_registration__)

    def test_verification_tokens_validation(self):
        """Checks that validation of verification tokens is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure verification token validation fails
        self.assertRaises(simple_acme_dns.errors.InvalidVerificationToken, client.__validate_verification_tokens__)

    def test_email_validation(self):
        """Checks that validation of registration is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure email validation fails
        self.assertRaises(simple_acme_dns.errors.InvalidEmail, client.__validate_email__)

    def test_directory_validation(self):
        """Checks that validation of the acme directory is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure email validation fails
        self.assertRaises(simple_acme_dns.errors.InvalidACMEDirectoryURL, client.__validate_directory__)

    def test_certificate_validation(self):
        """Checks that validation of the certificate is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure certificate validation fails
        self.assertRaises(simple_acme_dns.errors.InvalidCertificate, client.__validate_certificate__)

    def test_private_key_validation(self):
        """Checks that validation of the private_key is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure private_key validation fails
        self.assertRaises(simple_acme_dns.errors.InvalidPrivateKey, client.__validate_private_key__)

    def test_domain_validation(self):
        """Checks that validation of the domains is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure domains validation fails if domains attribute is empty
        self.assertRaises(simple_acme_dns.errors.InvalidDomain, client.__validate_domains__)

        # Ensure domains validation fails if domains are not a list
        client.domains = True
        self.assertRaises(simple_acme_dns.errors.InvalidDomain, client.__validate_domains__)

        # Ensure wildcard value gets stripped and that the remaining value is an FQDN
        client.domains = ["*.INVALID!!!"]
        self.assertRaises(simple_acme_dns.errors.InvalidDomain, client.__validate_domains__)

    def test_acme_timeout(self):
        """Tests that acme timeout error can be raised."""
        with self.assertRaises(simple_acme_dns.errors.ACMETimeout):
            raise simple_acme_dns.errors.ACMETimeout("test_acme_timeout")


if __name__ == '__main__':
    unittest.main()
