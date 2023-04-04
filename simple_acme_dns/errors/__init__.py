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
"""Custom exception classes for simple_acme_dns."""


class ChallengeUnavailable(Exception):
    """Error occurs when the requested ACME server does not offer the DNS-01 challenge"""
    def __init__(self, message: str) -> None:
        self.message = message


class OrderNotFound(Exception):
    """Error occurs when the requested ACME server does not offer the DNS-01 challenge"""
    def __init__(self, message: str) -> None:
        self.message = message


class InvalidCSR(Exception):
    """Error occurs when the requested CSR rtype is unsupported"""
    def __init__(self, message: str) -> None:
        self.message = message


class InvalidKeyType(Exception):
    """Error occurs when the requested private key rtype is unsupported"""
    def __init__(self, message: str) -> None:
        self.message = message


class InvalidPrivateKey(Exception):
    """Error occurs when the private key is used before it has been generated."""
    def __init__(self, message) -> None:
        self.message = message


class InvalidCertificate(Exception):
    """Error occurs when the certificate is invalid or does not exist."""
    def __init__(self, message: str) -> None:
        self.message = message


class InvalidAccount(Exception):
    """Error occurs when requests are made to the ACME server without registration"""
    def __init__(self, message: str) -> None:
        self.message = message


class InvalidEmail(Exception):
    """Error occurs when an account action was requested but no email value exists"""
    def __init__(self, message: str) -> None:
        self.message = message


class InvalidVerificationToken(Exception):
    """Error occurs when the client object does not contain required verification tokens"""
    def __init__(self, message: str) -> None:
        self.message = message


class InvalidDomain(Exception):
    """Error occurs when requests are made to the ACME server without a domains"""
    def __init__(self, message: str) -> None:
        self.message = message


class InvalidPath(Exception):
    """Error occurs when a request file path does not exist"""
    def __init__(self, message: str) -> None:
        self.message = message


class ACMETimeout(Exception):
    """Error occurs when the max time has been exceeded waiting for an ACME server event"""
    def __init__(self, message: str) -> None:
        self.message = message
