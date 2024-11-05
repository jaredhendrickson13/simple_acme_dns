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
"""
simple_acme_dns is a Python ACME client specifically tailored to the DNS-01 challenge. This makes it easy to manage ACME
certificates and accounts all within Python without the need for an external tool like `certbot`. Although this module
is intended for use with Let's Encrypt, it will support any CA utilizing the ACME v2 protocol.
"""
import datetime
import json
import pathlib
import time

import OpenSSL
import josepy as jose
import validators
from acme import challenges
from acme import client
from acme import crypto_util
from acme import messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from . import errors
from . import tools


# Constants and Variables
DNS_LABEL = '_acme-challenge'
__pdoc__ = {"tests": False}    # Excludes 'tests' submodule from documentation


class ACMEClient:
    """
    A basic ACME client object to interface with a CA using the ACME DNS-01 challenge.
    """
    # This package is all about user simplicity, keeping all items contained to one class supports this.
    # pylint: disable=too-many-instance-attributes,too-many-public-methods

    def __init__(
            self,
            domains: list = None,
            email: str = None,
            directory: str = "https://acme-staging-v02.api.letsencrypt.org/directory",
            nameservers: list = None,
            new_account: bool = False,
            generate_csr: bool = False,
            verify_ssl: bool = True
    ):
        """
        Args:
            domains (list): A list of domains to request a certificate for.
            email (str): An email address to use when registering new ACME accounts.
            directory (str): The ACME directory URL to interact with.
            nameservers (list): A list of DNS server hosts to query when checking DNS propagation.
            new_account (bool): Automatically create a new ACME account upon creation.
            generate_csr (bool): Automatically generate a new private key and CSR upon creation.
            verify_ssl (bool): Verify the SSL certificate of the ACME server when making requests. This only applies
                when creating a new account.

        Examples:
            >>> import simple_acme_dns
            >>> client = simple_acme_dns.ACMEClient(
            ...     domains=["test1.example.com", "test2.example.com"],
            ...     email="example@example.com",
            ...     directory="https://acme-staging-v02.api.letsencrypt.org/directory",
            ...     nameservers=["8.8.8.8", "1.1.1.1"],
            ...     new_account=True,
            ...     generate_csr=True
            ... )
        """
        self.csr = ''.encode()
        self.directory = directory
        self.directory_obj = None
        self.account_key = None
        self.account = None
        self.account_path = None
        self.nameservers = nameservers
        self.net = None
        self.order = None
        self.final_order = None
        self.responses = []
        self.answers = []
        self._domains = domains if domains else []
        self._email = email
        self._certificate = ''.encode()
        self._private_key = ''.encode()
        self._acme_client = None
        self._verification_tokens = {}

        # Automatically create a new account if requested
        if new_account:
            self.new_account(verify_ssl=verify_ssl)
        # Automatically create a new private key and CSR
        if generate_csr:
            self.generate_private_key_and_csr()

    def generate_csr(self) -> bytes:
        """
        Generates a new CSR using the object's `domains` and `private_key` attributes.

        Returns:
            bytes: The X509 CSR data bytes-string. This method will update the `csr` attribute of the object
                with the same value.

        Examples:
            >>> client.generate_csr()
            b'-----BEGIN CERTIFICATE REQUEST-----\\nMIHxMIGZAgECMAAwWTATBgckjkn...'
        """
        self.csr = crypto_util.make_csr(self.private_key, self.domains)
        return self.csr

    def generate_private_key(self, key_type: str = 'ec256') -> bytes:
        """
        Generates a new RSA or EC private key.

        Args:
            key_type (str): The requested `private_key` type. Options are: [`ec256`, `ec384`, `rsa2048`, `rsa4096`]

        Returns:
            bytes: The PEM encoded private key data bytes-string. This method will update the `private_key` property
                of the object with the same value.

        Raises:
            simple_acme_dns.errors.InvalidKeyType: When an unknown/unsupported `key_type` is requested.

        Examples:
            >>> client.generate_private_key(key_type="ec384")
            b'-----BEGIN EC PRIVATE KEY-----\\nMIGkAgEBBDAZRFNLcQdVJmLh42p8F4D92...'
        """
        # Generate a EC256 private key
        if key_type == 'ec256':
            key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self.private_key = key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption())
        # Generate a EC384 private key
        elif key_type == 'ec384':
            key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.private_key = key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption()
            )
        # Generate a RSA2048 private key
        elif key_type == 'rsa2048':
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
            self.private_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        # Generate a RSA4096 private key
        elif key_type == 'rsa4096':
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
            self.private_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        # Otherwise, the requested key type is not supported. Throw an error
        else:
            options = ['ec256', 'ec384', 'rsa2048', 'rsa4096']
            msg = f"Invalid private key rtype '{key_type}'. Options {options}"
            raise errors.InvalidKeyType(msg)
        return self.private_key

    def generate_private_key_and_csr(self, key_type: str = 'ec256') -> tuple:
        """
        Generates a new private key and CSR.

        Args:
            key_type (str): The requested `private_key` type. Options are: [`ec256`, `ec384`, `rsa2048`, `rsa4096`]

        Returns:
            tuple: A tuple with the first value containing the private key, the second value contains the CSR. This
                method will update the `private_key` and `csr` properties of this object with the same values.

        Examples:
            >>> client.generate_private_key_and_csr(key_type="rsa2048")
            (b'-----BEGIN PRIVATE KEY-----\\nMIIEvAIBA...', b'-----BEGIN CERTIFICATE REQUEST-----\\nMIHxM...')
        """
        self.generate_private_key(key_type=key_type)
        self.generate_csr()
        return self.private_key, self.csr

    def request_verification_tokens(self) -> dict:
        """
        Requests verification tokens from the ACME server for each `domains` value. These tokens must be uploaded as
        a DNS TXT record for each corresponding domain to complete verification.

        Returns:
            dict: A dictionary where the key is the domain name the DNS name, and the value is a list of verification
                token strings that must be uploaded as a TXT record for that DNS name.

        Examples:
            >>> client.request_verification_tokens()
            {
                "_acme-challenge.test1.example.com": ["moY32lkdsZ3VWHM1mdM..."],
                "_acme-challenge.test2.example.com": ["asldfkjslweietj23_b...", "nMIIEvAIBA2-212_w..."]
            }
        """
        # Variables
        verification_tokens = {}
        self.responses = {}
        self.order = self.acme_client.new_order(self.csr)

        # Loop through each domain being challenged
        for domain, challenge_items in self.challenges.items():
            # Ensure the ACME label is prefixed to this domain and the wildcard is removed
            domain = f"{DNS_LABEL}.{self.strip_wildcard(domain)}"

            # Loop through each challenge for this domain and extract the response and verification token from each
            for challenge in challenge_items:
                # Create a dict list item for this domain to store it's associated verification tokens in
                verification_tokens[domain] = verification_tokens[domain] if domain in verification_tokens else []

                # Obtain the response and validation items from this challenge
                response, validation = challenge.response_and_validation(self.acme_client.net.key)
                verification_tokens[domain].append(validation)

                # Save the response, so it can be looked up later using the challenge token
                self.responses[challenge.chall.token] = response

        # Set our new verification tokens and return the value
        self._verification_tokens = verification_tokens
        return self.verification_tokens

    def request_certificate(self, wait: int = 0, timeout: int = 90) -> bytes:
        """
        Requests a final verification answer from the ACME server and requests the certificate if verification was
        successful. If you request the certificate before DNS has propagated and verification fails, you must start
        the verification process over entirely by requesting new verification tokens.

        Args:
            wait (int): The amount of time (in seconds) to wait before requesting a challenge answer from the
                server. This is only necessary if you are not using the `check_dns_propagation()` method to verify the
                DNS records exist and would rather wait a specific amount of time instead.
            timeout (int): The amount of time (in seconds) to wait for the ACME server to respond with a certificate.
                If the ACME server does not respond within this time-frame, the request will be considered a failure.

        Returns:
            bytes: The PEM encoded certificate data bytes-string. This method will update the `certificate` attribute
                with this value.

        Examples:
            >>> client.request_certificate()
            b'-----BEGIN CERTIFICATE-----\\nMIIEfzCCA2egAwI...
        """
        # Allow the user to specify an amount of time to wait before requesting the certificate
        time.sleep(wait)
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

        # For each domain being challenged, request answers for their challenges
        for _, challenge_list in self.challenges.items():
            # Request an answer for each of this domain's challenges
            for challenge in challenge_list:
                self.answers.append(
                    self.acme_client.answer_challenge(challenge, self.responses[challenge.chall.token])
                )

        # Request our final order and save the certificate if successful
        self.final_order = self.acme_client.poll_and_finalize(self.order, deadline=deadline)
        self.certificate = self.final_order.fullchain_pem.encode()
        return self.certificate

    def revoke_certificate(self, reason: int = 0) -> None:
        """
        Attempts to revoke the existing certificate from the issuing ACME server.

        Args:
            reason (int): The numeric reason for revocation identifier. In most cases, this can be left as `0`.
                For more information, refer to: https://letsencrypt.org/docs/revoking/#specifying-a-reason-code

        Examples:
            >>> client.revoke_certificate()
        """
        # Load the certificate crypto object and request revocation from the ACME server
        cert_obj = jose.ComparableX509(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.certificate))
        self.acme_client.revoke(cert_obj, reason)

    def new_account(self, verify_ssl=True) -> None:
        """
        Registers a new ACME account at the set ACME `directory` URL. By running this method, you are agreeing to the
        ACME servers terms of use.

        Args:
            verify_ssl (bool): Verify the SSL certificate of the ACME server when making requests.

        Examples:
            >>> client.new_account()
        """
        # Generate a new RSA2048 account key
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.account_key = jose.JWKRSA(key=rsa_key)

        # Initialize our ACME client object
        self.net = client.ClientNetwork(self.account_key, user_agent='simple_acme_dns/v2', verify_ssl=verify_ssl)
        self.directory_obj = messages.Directory.from_json(self.net.get(self.directory).json())
        self.acme_client = client.ClientV2(self.directory_obj, net=self.net)

        # Complete registration
        registration = messages.NewRegistration.from_data(email=self._email, terms_of_service_agreed=True)
        self.account = self.acme_client.new_account(registration)

    def deactivate_account(self, delete: bool = True) -> None:
        """
        Deactivates the current account registration. This action is irreversible.

        Args:
            delete (bool): Indicate whether the associated account file on the local system should also be
                deleted after deactivation.

        Examples:
            >>> client.deactivate_account()
        """
        # Tell the ACME server to deactivate this account
        self.acme_client.deactivate_registration(self.account)

        # If this object contains a linked file path, and deletion is requested, delete the linked file
        if self.account_path and delete:
            # Delete the file if it's present
            try:
                pathlib.Path(self.account_path).unlink()
            except FileNotFoundError:
                pass

    def export_account(self, save_certificate: bool = True, save_private_key: bool = False) -> str:
        """
        Exports the object as a JSON string. This allows the ACME account data to be exported to a string that can
        be re-imported for use later.

        Args:
            save_certificate (bool): Indicate whether the existing certificate should also be stored in the
                JSON string.
            save_private_key (booL): Indicate whether the private key should also be stored in the JSON string.

        Returns:
            str: The current object encoded as a JSON string.

        Examples:
            >>> client.export_account(save_certificate=True, save_private_key=True)
            '{"account": {"body": {"key": {"n": "vtByzpW..."}}}}'
        """
        # Format our object into a serializable format
        acct_data = {
            'account': self.account.to_json(),
            'account_key': self.account_key.json_dumps(),
            'directory': self.directory,
            'verify_ssl': self.net.verify_ssl,
            'domains': self._domains,
            'certificate': self.certificate.decode() if save_certificate else '',
            'private_key': self.private_key.decode() if save_private_key else ''
        }

        return json.dumps(acct_data)

    def export_account_to_file(
            self,
            path: str = '.',
            name: str = 'account.json',
            save_certificate: bool = True,
            save_private_key: bool = False
    ) -> None:
        """
        Exports the object as a JSON string. This allows the ACME account data to be exported to a file that can
        be re-imported for use later.

        Args:
            path (str): The directory path to save the account file to. Defaults to the current working directory.
            name (str): The file name to save. Defaults to `account.json`.
            save_certificate (bool): Indicate whether the existing certificate should also be stored in the
                JSON string.
            save_private_key (booL): Indicate whether the private key should also be stored in the JSON string.

        Raises:
            simple_acme_dns.errors.InvalidPath: when the requested directory path does not exist.

        Examples:
            >>> client.export_account_to_file(
            ...     path="/tmp/",
            ...     name="my_acme_account.json",
            ...     save_certificate=True,
            ...     save_private_key=True
            ... )
        """
        dir_path = pathlib.Path(path).absolute()

        # Ensure our path is an existing directory, throw an error otherwise
        if dir_path.is_dir():
            # Open the file and write our JSON content
            with open(str(dir_path.joinpath(name)), 'w', encoding="utf-8") as account_file:
                account_file.write(self.export_account(save_certificate, save_private_key))
                self.account_path = str(dir_path.joinpath(name))
        else:
            msg = f"Directory at '{path}' does not exist."
            raise errors.InvalidPath(msg)

    @staticmethod
    def load_account(json_data: str) -> 'ACMEClient':
        """
        Loads an existing account from a JSON data string created by the `export_account()` method.

        Args:
            json_data (str): The JSON account data string to import.

        Returns:
            simple_acme_dns.ACMEClient: The imported ACMEClient object.

        Examples:
            >>> client = simple_acme_dns.ACMEClient.load_account('{"account": {"body": {"key": {"n": "vtByzpW..."}}}}')
        """
        acct_data = json.loads(json_data)
        obj = ACMEClient()

        # Format the serialized data back into the object
        verify_ssl = acct_data.get('verify_ssl', True)
        obj.directory = acct_data.get('directory', None)
        obj.domains = acct_data.get('domains', [])
        obj.certificate = acct_data.get('certificate', '').encode()
        obj.private_key = acct_data.get('private_key', '').encode()
        if acct_data['account']['body']['contact']:
            obj.email = acct_data['account']['body']['contact'][0].replace('mailto:', '')
        obj.account = messages.RegistrationResource.json_loads(json.dumps(acct_data['account']))
        obj.account_key = jose.JWKRSA.json_loads(acct_data['account_key'])

        # Re-initialize the ACME client and registration
        obj.net = client.ClientNetwork(obj.account_key, user_agent='simple_acme_dns/1.0.0', verify_ssl=verify_ssl)
        obj.directory_obj = messages.Directory.from_json(obj.net.get(obj.directory).json())
        obj.acme_client = client.ClientV2(obj.directory_obj, net=obj.net)
        obj.account = obj.acme_client.query_registration(obj.account)

        return obj

    @staticmethod
    def load_account_from_file(filepath: str) -> 'ACMEClient':
        """
        Loads an existing account from a JSON file created by the `export_account_to_file()` method.

        Args:
            filepath (str): The JSON file path to import.

        Returns:
            simple_acme_dns.ACMEClient: The imported ACMEClient object.

        Raises:
            simple_acme_dns.errors.InvalidPath: When the JSON file path does not exist.

        Examples:
            >>> client = simple_acme_dns.ACMEClient.load_account('/tmp/my_acme_account.json')
        """
        filepath = pathlib.Path(filepath).absolute()

        # Ensure our file exists, throw an error otherwise
        if filepath.exists():
            # Open our file and read it's contents.
            with open(filepath, 'r', encoding="utf-8") as json_file:
                json_data = json_file.read()

            # Load contents into a new object.
            obj = ACMEClient.load_account(json_data)
            obj.account_path = filepath
        else:
            raise errors.InvalidPath(f"No JSON account file found at '{filepath}'")

        return obj

    def check_dns_propagation(
            self,
            timeout: int = 300,
            interval: int = 2,
            authoritative: bool = False,
            round_robin: bool = True,
            verbose: bool = False
    ) -> bool:
        """
        Check's each of our domain's TXT record until the value matches it's verification token or until the timeout is
        reached. This method should be executed before executing the `request_certificates()` method. This method can
        take several minutes to complete, ensure you adjust the timeout value accordingly.

        Args:
            timeout (int): The amount of time (in seconds) to continue trying to verify the TXT records.
            interval (int): The amount of time (in seconds) between DNS requests per domain.
            authoritative (bool): Identify and use the authoritative nameserver for each domain instead of the
                `nameservers` values.
            round_robin (bool): Rotate between each nameserver instead of the default failover behavior.
            verbose (bool): Print DNS answers to the console.

        Returns:
            bool: A boolean indicating whether all the `domains` correctly return their verification token in
                the corresponding TXT records.

        Examples:
            >>> client.nameservers = ["8.8.8.8", "1.1.1.1"]
            >>> client.check_dns_propagation(
            ...     timeout=180,
            ...     interval=5,
            ...     authoritative=False,
            ...     round_robin=True,
            ...     verbose=False
            ... )
            Token 'moY3Cd0...' for '_acme-challenge.test1.example.com' not found in [] via 8.8.8.8
            Token 'O32-fd_...' for '_acme-challenge.test2.example.com' not found in [] via 8.8.8.8
            Token 'moY3Cd0...' for '_acme-challenge.test1.example.com' not found in [] via 1.1.1.1
            Token 'O32-fd_...' for '_acme-challenge.test2.example.com' found in ['O32-fd_...'] via 1.1.1.1
            Token 'moY3Cd0...' for '_acme-challenge.test1.example.com' not found in [] via 8.8.8.8
            Token 'moY3Cd0...' for '_acme-challenge.test1.example.com' not found in [] via 1.1.1.1
            Token 'moY3Cd0...' for '_acme-challenge.test1.example.com' found in ['moY3Cd0...'] via 8.8.8.8
            True
        """
        # Variables
        verified = []
        resolvers = []
        timeout = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

        # Create a DNS resolver objects for each domain being verified.
        for domain, tokens in self._verification_tokens.items():
            # Create a resolver for each token required for verification of this domain.
            for token in tokens:
                resolv = tools.DNSQuery(
                    domain,
                    rtype='TXT',
                    authoritative=authoritative,
                    nameservers=self.nameservers,
                    round_robin=round_robin
                )
                resolvers.append((domain, token, resolv))

        # Loop until we have exceeded our timeout value
        while datetime.datetime.now() < timeout:
            # Loop through each domain being verified
            for domain, token, resolver in resolvers:
                # Only try to verify the domain if it has not already been verified
                if token not in verified:
                    resolver.resolve()
                    # Save this domain as verified if our token was found in the TXT record values
                    if token in resolver.values:
                        verified.append(token)
                    # If verbose mode is enabled, print the results to the console
                    if verbose:
                        action = ('found' if token in verified else 'not found')
                        values = resolver.values
                        nameserver = resolver.last_nameserver
                        msg = f"Token '{token}' for '{domain}' {action} in {values} via {nameserver}"
                        print(msg)

            # Check that all resolvers completed verification
            if len(verified) == len(resolvers):
                return True

            # Avoid flooding the DNS server(s) by briefly pausing between DNS checks
            time.sleep(interval)

        return False

    @staticmethod
    def strip_wildcard(domain: str) -> str:
        """
        Strips the wildcard portion of a domain (*.) if present.

        Args:
            domain (str): The domain string to strip wildcards from.

        Returns:
            str: The domain string without the wildcard portion.
        """
        # If wildcard domain, strip of the wildcard to validate domain
        return domain[2:] if domain[:2].startswith("*.") else domain

    @property
    def challenges(self) -> dict:
        """
        Getter for the `challenges` property. Returns current DNS challenges found in our current ACME order.

        Returns:
            dict: A dictionary where the key is the domain name, and the value is a list of Challenge objects.

        Raises:
            simple_acme_dns.errors.OrderNotFound: When this property is called before the `order` object exists.
        """
        # Variables
        challs = {}

        # Do not allow this property to be called if an order has not been created beforehand.
        if not self.order:
            raise errors.OrderNotFound("Cannot get 'challenges' without an ACME order.")

        # Loop through each of our authorizations
        for auth in list(self.order.authorizations):
            # Loop through each authorization's available challenges
            for challenge in auth.body.challenges:
                # If this challenge is a DNS01 Challenege object, add it to our challenges.
                if isinstance(challenge.chall, challenges.DNS01):
                    # Capture the original domain requested
                    domain = auth.body.identifier.value
                    # Add this challenge to the dictionary item for this authorization's domain name
                    challs[domain] = challs[domain] if domain in challs else []
                    challs[domain].append(challenge)

        # If no challenges were found, throw an error
        if not challs:
            msg = f"ACME server at '{self.directory}' does not support DNS-01 challenge."
            raise errors.ChallengeUnavailable(msg.format(directory=str(self.directory)))

        return challs

    @property
    def acme_client(self) -> client.ClientV2:
        """
        Getter for the `client` property. This checks that the ACME client is set up whenever it's referenced.

        Returns:
            acme.client.ClientV2: The ClientV2 object needed to interact with the ACME server.

        Raises:
            simple_acme_dns.errors.InvalidAccount: When no account registration is configured for this object.
        """
        if not isinstance(self._acme_client, client.ClientV2):
            msg = 'No account registration found. You must register a new account or load an existing account first.'
            raise errors.InvalidAccount(msg)

        return self._acme_client

    @acme_client.setter
    def acme_client(self, value: client.ClientV2):
        """
        Setter for the `acme_client` property. This ensures the acme_client is an acme.client.ClientV2 object

        Args
         value (str): The `acme_client` value being set.

        Raises:
            simple_acme_dns.errors.InvalidAccount: When the `value` is not a valid email address
        """
        if not isinstance(value, client.ClientV2):
            msg = f"Value '{value}' is not an acme.client.ClientV2 object."
            raise errors.InvalidAccount(msg)

        self._acme_client = value

    @property
    def email(self) -> str:
        """
        Getter for the `email` property. This checks that an email exists when it's referenced.

        Returns:
            str:  A string representation of the email address

        Raises:
            simple_acme_dns.errors.InvalidEmail: When `email` is not set.

        """
        if not self._email:
            msg = 'No account email found. You must set the _email value first.'
            raise errors.InvalidEmail(msg)

        return self._email

    @email.setter
    def email(self, value: str):
        """
        Setter for the `email` property. This ensures an email address is valid before setting.

        Args
         value (str): The `email` value being set.

        Raises:
            simple_acme_dns.errors.InvalidEmail: When the `value` is not a valid email address
        """
        if not validators.email(value):
            msg = f"Value '{value}' is not a valid email address."
            raise errors.InvalidEmail(msg)

        self._email = value

    @property
    def verification_tokens(self) -> dict:
        """
        Getter for the `verification_tokens` property. This checks that verification tokens already
        exist whenever they are referenced.

        Returns:
            dict: A dictionary where the key is the verification domain name, and the value is a list of tokens for
                that domain. A DNS TXT entry must be created for each domain name with each of it's corresponding
                tokens as the TXT value.

        Raises:
            simple_acme_dns.errors.InvalidVerificationToken: When no verification tokens have been requested using
                the `request_verification_tokens()` method.
        """
        if not self._verification_tokens:
            msg = 'No verification tokens found. You must run request_verification_tokens() first.'
            raise errors.InvalidVerificationToken(msg)

        return self._verification_tokens

    @property
    def domains(self) -> list:
        """
        Getter for the `domains` property. This checks that domains are already set whenever it's referenced.

        Returns:
            list: A list of domain names currently set.

        Raises:
             simple_acme_dns.errors.InvalidDomain: When no `domains` have been set.
        """
        if not self._domains:
            msg = 'No domains found. You must set the domains value first.'
            raise errors.InvalidDomain(msg)

        return self._domains

    @domains.setter
    def domains(self, value) -> None:
        """
        Setter for the `domains` property. This checks that the assigned domains value is a list of valid FQDNs.

        Args:
            value (str): A list of domains to be set.

        Returns:
            list: A list of valid domain names.

        Raises:
            simple_acme_dns.errors.InvalidDomain: When one or more domains are invalid.
        """
        # Ensure set value is a list
        if not isinstance(value, list):
            msg = "Domains must be of type 'list'."
            raise errors.InvalidDomain(msg)

        # Ensure each domain within the list is an RFC2181 compliant hostname
        for domain in value:
            # Check that value (minus the wildcard if present) is a valid FQDN
            if not validators.domain(self.strip_wildcard(domain)):
                msg = f"Invalid domain name '{domain}'. Domain name must adhere to RFC2181."
                raise errors.InvalidDomain(msg)

        # If we've made it this far, the value is valid. Set it.
        self._domains = value

    @property
    def csr(self) -> bytes:
        """
        Getter for the `csr` property. This checks that a CSR is already set whenever it's referenced.

        Returns:
            bytes: The current PEM encoded CSR data bytes-string if present.

        Raises:
            simple_acme_dns.errors.InvalidCSR: When the `csr` value has not been set yet.
        """
        # Throw an error if the CSR is referenced before it is set
        if not self._csr:
            raise errors.InvalidCSR("CSR value must be set before referencing 'csr'.")

        return self._csr

    @csr.setter
    def csr(self, value: bytes) -> None:
        """
        Setter for the 'csr' property. This ensures the set value is a bytes-string.

        Args:
            value (bytes): The CSR value being set.

        Raises:
            simple_acme_dns.errors.InvalidCSR: When the `csr` value being set is not of type `bytes`.
        """
        # Convert string assignments to bytes
        if not isinstance(value, bytes):
            raise errors.InvalidCSR("CSR must be type 'bytes'.")

        self._csr = value

    @property
    def certificate(self) -> bytes:
        """
        Getter for the `certificate` property. This checks that a certificate is already set whenever it's referenced.

        Returns:
            bytes: The current PEM encoded certificate data bytes-string if present.
        """
        return self._certificate

    @certificate.setter
    def certificate(self, value: bytes) -> None:
        """
        Setter for the 'certificate' property. This ensures the set value is a bytes-string.

        Args:
            value (bytes): The certificate value being set.

        Raises:
            simple_acme_dns.errors.InvalidCertificate: When the `certificate` value being set is not of type `bytes`.
        """
        # Convert string assignments to bytes
        if not isinstance(value, bytes):
            raise errors.InvalidCertificate("Certificate must be type 'bytes'.")

        self._certificate = value

    @property
    def private_key(self) -> bytes:
        """
        Getter for the 'private_key' property. This checks that a private_key is already set whenever it's referenced.

        Returns:
            bytes: The PEM encoded `private_key` bytes-string that is currently set if present.
        """
        return self._private_key

    @private_key.setter
    def private_key(self, value: bytes) -> None:
        """
        Setter for the 'private_key' property. This ensures the set value is a bytes-string.

        Args:
            value (bytes): The `private_key` value being set.

        Raises:
            simple_acme_dns.errors.InvalidPrivateKey: When no `private_key` value has been set.
        """
        # Convert string assignments to bytes
        if not isinstance(value, bytes):
            raise errors.InvalidPrivateKey("Private key must be type 'bytes'.")

        self._private_key = value
