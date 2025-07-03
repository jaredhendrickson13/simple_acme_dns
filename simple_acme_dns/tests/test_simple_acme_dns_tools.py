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
"""Tests tools used by the simple_acme_dns package and tests."""
import unittest
from simple_acme_dns.tests.tools import is_csr, is_cert, is_json, is_private_key


class TestSimpleAcmeDnsTools(unittest.TestCase):
    """Tests tools functions used both by tests and the main package."""

    def test_is_csr(self):
        """Tests the is_csr testing tools function"""
        # Variables
        good_csr = b"-----BEGIN CERTIFICATE REQUEST-----MPJQRfevIpoy3hsvKMzvZ..."
        bad_csr = b"-----BEGIN CERTIFICATE-----MPJQRfevIpoy3hsvKMzvZ..."

        # Ensure the good CSR returns true and the bad CSR returns false
        self.assertTrue(is_csr(good_csr))
        self.assertFalse(is_csr(bad_csr))

    def test_is_cert(self):
        """Tests the is_cert testing tools function"""
        # Variables
        good_cert = b"-----BEGIN CERTIFICATE-----MPJQRfevIpoy3hsvKMzvZ..."
        bad_cert = b"-----BEGIN CERTIFICATE REQUEST-----MPJQRfevIpoy3hsvKMzvZ..."

        # Ensure the good cert returns true and the bad cert returns false
        self.assertTrue(is_cert(good_cert))
        self.assertFalse(is_cert(bad_cert))

    def test_is_private_key(self):
        """Tests the is_private_key testing tools function"""
        # Variables
        good_rsa_private_key = b"-----BEGIN PRIVATE KEY-----MPJQRfevIpoy3hsvKMzvZ..."
        good_ec_private_key = b"-----BEGIN EC PRIVATE KEY-----MPJQRfevIpoy3hsvKMzvZ..."
        bad_private_key = b"-----BEGIN CERTIFICATE REQUEST-----MPJQRfevIpoy3hsvKMzvZ..."

        # Ensure the good keys return true and the bad key returns false
        self.assertTrue(is_private_key(good_rsa_private_key, key_type="rsa2048"))
        self.assertTrue(is_private_key(good_ec_private_key, key_type="ec384"))
        self.assertFalse(is_private_key(bad_private_key, key_type="rsa2048"))
        self.assertFalse(is_private_key(bad_private_key, key_type="ec384"))

    def test_is_json(self):
        """Tests the is_json testing tools function."""
        # Variables
        good_json = '{"simple_acme_dns": {"test": true}}'
        bad_json = "{simple_acme_dns: {test: True}"

        # Ensure the good json returns true and the bad json returns false
        self.assertTrue(is_json(good_json))
        self.assertFalse(is_json(bad_json))


if __name__ == "__main__":
    unittest.main()
