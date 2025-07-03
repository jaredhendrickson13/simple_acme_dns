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
"""Tools for unit testing."""
import json
import os

from google.cloud import dns


# Functions
def is_cert(cert: bytes) -> bool:
    """Checks if a given cert is PEM formatted certificate."""
    # Check for PEM cert
    if cert.startswith(b"-----BEGIN CERTIFICATE-----"):
        return True

    return False


def is_private_key(private_key: bytes, key_type: str) -> bool:
    """Checks if a given private key matches a specific key type."""
    # Check for RSA keys
    if key_type.startswith("rsa") and private_key.startswith(
        b"-----BEGIN PRIVATE KEY-----"
    ):
        return True
    if key_type.startswith("rsa") and private_key.startswith(
        b"-----BEGIN RSA PRIVATE KEY-----"
    ):
        return True

    # Check for EC keys
    if key_type.startswith("ec") and private_key.startswith(
        b"-----BEGIN EC PRIVATE KEY-----"
    ):
        return True

    return False


def is_csr(csr: bytes) -> bool:
    """Checks if a given bytes is a CSR"""
    if csr.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
        return True

    return False


def is_json(data: str) -> bool:
    """Checks if a string is valid JSON."""
    try:
        json.loads(data)
    except ValueError as _:
        return False

    return True


class GoogleDNSClient:
    """
    Client for Google Cloud DNS. This is used to automatically upload the ACME verification tokens to
    Google Cloud DNS to complete the DNS-01 challenge when requesting certificates.
    """

    def __init__(self, name: str, rtype: str, ttl: int, data: str) -> None:
        """
        Assigns required parameters to object attributes and assigns default attributes
        :param name: the FQDN of the DNS record to create/update/delete in string format
        :param rtype: the DNS record type to assign when creating/updating DNS records in string format.
        :param ttl: a time-to-live value for the DNS record to create/update in integer format
        :param data: the data values to assign the DNS record in list format
        """
        # Authenticate by loading the JSON service file via the GCLOUD_DNS_JSON enviroment variable
        service_account_json = json.loads(os.environ.get("GCLOUD_DNS_JSON", "{}"))
        self.client = dns.Client.from_service_account_info(service_account_json)

        # Set object attributes
        self.name = name + "."
        self.rtype = rtype.upper()
        self.ttl = ttl
        self.data = data
        self.zone = None
        self.record = None
        self.get_zone()

    def get_zone(self) -> (dns.ManagedZone, None):
        """
        Retrieves each DNS zones the GCLOUD_DNS_JSON has access to
        :return: the DNSZone object
        """

        # Loop through each available zone and select the matching zone
        for zone in self.client.list_zones():
            # Check if this zone matches our DNS name
            if self.name.endswith(zone.dns_name):
                self.zone = zone
                return zone

        return None

    def get_record(self) -> (dns.ResourceRecordSet, None):
        """
        Retrieves an existing record for the name and rtype specified in this object
        :return: a DNSRecord object
        """

        # Loop through each resource in this zone and select the matching one, or create if missing
        for record in self.zone.list_resource_record_sets():
            # Check if this record matches
            if record.name == self.name and record.record_type == self.rtype:
                self.record = record
                return record

        return None

    def create_record(self, replace: bool = False) -> None:
        """
        Creates a new DNS record with our current name, rtype, ttl and data attributes
        :param replace: a boolean specifiying whether existing records should be replaced
        :return: None, the record will be created in Google Cloud DNS after running
        """

        # Remove the existing record if it exists
        if replace and self.get_record():
            self.delete_record()

        # Create our new record and format the change request
        self.record = self.zone.resource_record_set(
            self.name, self.rtype, self.ttl, self.data
        )
        change = self.zone.changes()
        change.add_record_set(self.record)
        change.create()

        # Wait for server response
        while change.status != "done":
            change.reload()

    def delete_record(self) -> None:
        """
        Deletes an existing DNS record matching our current name and rtype
        :return: None, the record will be created in Google Cloud DNS after running
        """

        # Delete our record and format the change request
        self.get_record()
        change = self.zone.changes()
        change.delete_record_set(self.record)
        change.create()

        # Wait for server response
        while change.status != "done":
            change.reload()
