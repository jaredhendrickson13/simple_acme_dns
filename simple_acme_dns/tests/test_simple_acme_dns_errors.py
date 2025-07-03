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

        # Ensure an error is thrown if challenges are requested before an order is placed
        with self.assertRaises(simple_acme_dns.errors.OrderNotFound):
            return client.challenges

        # Ensure an error is thrown if there are no available challenges
        client.order = MockOrder()
        with self.assertRaises(simple_acme_dns.errors.ChallengeUnavailable):
            return client.challenges

    def test_registration_validation(self):
        """Checks that validation of registration is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure registration validation fails
        with self.assertRaises(simple_acme_dns.errors.InvalidAccount):
            return client.acme_client

        # Ensure 'acme_client' cannot be assigned a value unless it is an acme.client.ClientV2 object.
        with self.assertRaises(simple_acme_dns.errors.InvalidAccount):
            client.acme_client = "Not an acme.client.ClientV2 object"

    def test_verification_tokens_validation(self):
        """Checks that validation of verification tokens is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure verification token validation fails
        with self.assertRaises(simple_acme_dns.errors.InvalidVerificationToken):
            return client.verification_tokens

    def test_email_validation(self):
        """Checks that validation of registration is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure email validation fails if email is set to a non-email address value
        with self.assertRaises(simple_acme_dns.errors.InvalidEmail):
            client.email = "Not a valid email address!"

    def test_csr_validation(self):
        """Checks that validation of the certificate is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure CSR raises an error when it is referrenced before a value is assigned
        with self.assertRaises(simple_acme_dns.errors.InvalidCSR):
            return client.csr

        # Ensure CSR cannot be assigned a non-bytes type value
        with self.assertRaises(simple_acme_dns.errors.InvalidCSR):
            client.csr = "Not a bytes string."

    def test_certificate_validation(self):
        """Checks that validation of the certificate is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure certificate validation fails
        with self.assertRaises(simple_acme_dns.errors.InvalidCertificate):
            client.certificate = "Not a bytes string."

    def test_private_key_validation(self):
        """Checks that validation of the private_key is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure private_key validation fails
        with self.assertRaises(simple_acme_dns.errors.InvalidPrivateKey):
            client.private_key = "Not a bytes string."

    def test_domain_validation(self):
        """Checks that validation of the domains is performed."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient()

        # Ensure domains validation fails if domains attribute is empty
        with self.assertRaises(simple_acme_dns.errors.InvalidDomain):
            return client.domains

        # Ensure domains validation fails if domains are not a list
        with self.assertRaises(simple_acme_dns.errors.InvalidDomain):
            client.domains = "Not a list"

        # Ensure wildcard value gets stripped and that the remaining value is an FQDN
        with self.assertRaises(simple_acme_dns.errors.InvalidDomain):
            client.domains = ["*.INVALID!!!"]

    def test_acme_timeout(self):
        """Tests that acme timeout error can be raised."""
        with self.assertRaises(simple_acme_dns.errors.ACMETimeout):
            raise simple_acme_dns.errors.ACMETimeout("test_acme_timeout")

    def test_profile(self) -> None:
        """Tests that profile validation raises an error when the ACME server doesn't support."""
        # Create a new client for this test
        client = simple_acme_dns.ACMEClient(
            domains=simple_acme_dns.tests.TEST_DOMAINS,
            directory=simple_acme_dns.tests.TEST_DIRECTORY,
            new_account=True
        )

        # Ensure profile cannot be set to a non-supported profile
        with self.assertRaises(simple_acme_dns.errors.InvalidProfile):
            client.profile = "INVALID_PROFILE"

    def test_user_agent(self) -> None:
        """Tests that user agent validation raises an erro
        r when the ACME server doesn't support."""
        client = simple_acme_dns.ACMEClient()

        # Ensure user agent cannot be set to a non-supported user agent
        with self.assertRaises(simple_acme_dns.errors.InvalidUserAgent):
            client.user_agent = 12345


if __name__ == "__main__":
    unittest.main()
