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
__pdoc = {"tests": False}    # Excludes 'tests' submodule from documentation
__doc = """
simple_acme_dns is a Python ACME client specifically tailored to the DNS-01 challenge. This makes it easy to manage ACME 
certificates and accounts all within Python without the need for an external tool like `certbot`. Although this module 
is intended for use with Let's Encrypt, it will support any CA utilizing the ACME v2 protocol. 
"""


class ACMEClient:
    """
    A basic ACME client object to interface with a CA using the ACME DNS-01 challenge.\n
    - :var `certificate` [`bytes`]: the PEM formatted certificate. This value is populated after successfully running
    the `request_certificate()` methood.\n
    - :var `private_key` [`bytes`]: the PEM formatted private key. This value is populated after successfully running
    the `generate_private_key()` method.\n
    - :var `csr` [`bytes`]: the PEM formatted certificate signing request. This value is populated after successfully
    running the `generate_csr()` method.\n
    """

    def __init__(
            self,
            domains: list = None,
            email: str = None,
            directory: str = "https://acme-staging-v02.api.letsencrypt.org/directory",
            nameservers: list = None,
            new_account: bool = False,
            generate_csr: bool = False
    ):
        """
        - :param `__domains__` [`list`]: FQDNs to list in the certificate (SANS).\n
        - :param `_email` [`str`]: a valid _email address to register new ACME accounts with.\n
        - :param `_directory` [`str`]: the ACME _directory URL.\n
        - :param `_nameservers` [`list`]: _nameservers to use when querying DNS. Defaults to system _nameservers.\n
        - :param `new_account` [`bool`]: automatically register a new account upon object creation. A `_directory` and
        `_email` value will be required if True.\n
        - :param `generate_csr` [`bool`]: generate a new private key and CSR upon object creation. A `__domains__` value
        will be required if True.\n\n

        ## Example:\n
        ```python
        >>> import simple_acme_dns
        >>> client = simple_acme_dns.ACMEClient(
        ...     __domains__=["test1.example.com", "test2.example.com"],
        ...     _email="example@example.com",
        ...     _directory="https://acme-staging-v02.api.letsencrypt.org/directory",
        ...     _nameservers=["8.8.8.8", "1.1.1.1"],
        ...     new_account=True,
        ...     generate_csr=True
        ... )
        ```
        """
        self.csr = ''.encode()
        self.directory = directory
        self._directory_obj = None
        self.account_key = None
        self.account = None
        self.account_path = None
        self._domains = domains if domains else []
        self._email = email
        self._certificate = ''.encode()
        self._private_key = ''.encode()
        self._nameservers = nameservers
        self._client = None
        self._net = None
        self._order = None
        self._final_order = None
        self._verification_tokens = {}
        self._responses = []
        self._answers = []

        # Automatically create a new account if requested
        if new_account:
            self.new_account()
        # Automatically create a new private key and CSR
        if generate_csr:
            self.generate_private_key_and_csr()

    def generate_csr(self) -> bytes:
        """
        Generates a new CSR using the object's `__domains__` and `private_key` values.\n
        - :return [`bytes`]: the encoded CSR PEM data string. This method will update the `csr` property of the object
        with the same value.\n
        - :raises `InvalidDomain`: when no valid `domains` are set.\n
        - :raises `InvalidPrivateKey`: when no `private_key` exists for this object.\n\n

        ## Example\n
        ```python
        >>> client.generate_csr()
        b'-----BEGIN CERTIFICATE REQUEST-----\\nMIHxMIGZAgECMAAwWTATBgckjkn...'
        ```
        """
        #
        self.csr = crypto_util.make_csr(self.private_key, self.domains)
        return self.csr

    def generate_private_key(self, key_type: str = 'ec256') -> bytes:
        """
        Generates a new RSA or EC private key.\n
        - :param `key_type` [`str`]: the requested `private_key` type. Options are: [`ec256`, `ec384`, `rsa2048`,
        `rsa4096`]\n
        - :return [`bytes`]: the encoded private key PEM data string. This method will update the `private_key` property
         of the object with the same value.\n
        - :raises `InvalidKeyType`: when an unknown/unsupported `key_type` is requested\n\n

        ## Example\n
        ```python
        >>> client.generate_private_key(key_type="ec384")
        b'-----BEGIN EC PRIVATE KEY-----\\nMIGkAgEBBDAZRFNLcQdVJmLh42p8F4D92...'
        ```
        """
        # Generate a EC256 private key
        if key_type == 'ec256':
            key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self._private_key = key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption())
        # Generate a EC384 private key
        elif key_type == 'ec384':
            key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self._private_key = key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption()
            )
        # Generate a RSA2048 private key
        elif key_type == 'rsa2048':
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
            self._private_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        # Generate a RSA4096 private key
        elif key_type == 'rsa4096':
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
            self._private_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        # Otherwise, the requested key type is not supported. Throw an error
        else:
            options = ['ec256', 'ec384', 'rsa2048', 'rsa4096']
            msg = f"Invalid private key rtype '{key_type}'. Options {options}"
            raise errors.InvalidKeyType(msg)
        return self._private_key

    def generate_private_key_and_csr(self, key_type: str = 'ec256') -> tuple:
        """
        Generates a new private key and CSR.\n
        - :param `key_type` [`str`]: the requested `private_key` type. Options are: [`ec256`, `ec384`, `rsa2048`,
        `rsa4096`]\n
        - :return [`tuple`]: first value contains the key, the second value contains the CSR. This method will update
        the `private_key` and `csr` properties of this object with the same values.\n\n

        ## Example\n
        ```python
        >>> client.generate_private_key_and_csr(key_type="rsa2048")
        (b'-----BEGIN PRIVATE KEY-----\\nMIIEvAIBA...', b'-----BEGIN CERTIFICATE REQUEST-----\\nMIHxM...')
        ```
        """
        self.generate_private_key(key_type=key_type)
        self.generate_csr()
        return self.private_key, self.csr

    def request_verification_tokens(self) -> dict:
        """
        Requests verification tokens from the ACME server for each `_domains` value. These tokens must be uploaded as
        a DNS TXT record for each corresponding domain to complete verification.\n
        - :return [`dict`]: a dict where the key is the domain
        - :raises `InvalidAccount`: when account registration has not been set.\n\n

        ## Example\n
        ```python
        >>> client.request_verification_tokens()
        [
            ('_acme-challenge.test1.example.com', 'moY32lkdsZ3VWHM1mdM...'),
            ('_acme-challenge.test2.example.com', 'asldfkjslweietj23_b...')
        ]
        ```
        """
        # Variables
        verification_tokens = {}
        self._responses = {}
        self._order = self._client.new_order(self.csr)

        # Loop through each domain being challenged
        for domain, challenge_items in self._challenges.items():
            # Ensure the ACME label is prefixed to this domain and the wildcard is removed
            domain = f"{DNS_LABEL}.{self.strip_wildcard(domain)}"

            # Loop through each challenge for this domain and extract the response and verification token from each
            for challenge in challenge_items:
                # Create a dict list item for this domain to store it's associated verification tokens in
                verification_tokens[domain] = verification_tokens[domain] if domain in verification_tokens else []

                # Obtain the response and validation items from this challenge
                response, validation = challenge.response_and_validation(self._client.net.key)
                verification_tokens[domain].append(validation)

                # Save the response, so it can be looked up later using the challenge token
                self._responses[challenge.chall.token] = response

        # Set our new verification tokens and return the value
        self._verification_tokens = verification_tokens
        return self.verification_tokens

    def request_certificate(self, wait: int = 0, timeout: int = 90) -> bytes:
        """
        Requests a final verification answer from the ACME server and requests the certificate if verification was
        successful. If you request the certificate before DNS has propagated and verification fails, you must start
        the verification process over entirely by requesting new verification tokens.\n
        - :param `wait` [`int`]: amount of time (in seconds) to wait before requesting a challenge answer from the
        server. This is only necessary if you are not using the `check_dns_propagation()` method to verify the DNS
        records exist and would rather wait a specific amount of time.\n
        - :return [`bytes`]: the PEM encoded certificate. This method will update the `certificate` and `csr` property
        of this object with the same value.\n
        - :raises `InvalidAccount`:  when account registration has not been set.\n\n

        ## Example\n
        ```python
        >>> client.request_certificate()
        b'-----BEGIN CERTIFICATE-----\\nMIIEfzCCA2egAwI...
        ```
        """
        # Allow the user to specify an amount of time to wait before requesting the certificate
        time.sleep(wait)
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

        # For each domain being challenged, request answers for their challenges
        for domain, challenge_list in self._challenges.items():
            # Request an answer for each of this domain's challenges
            for challenge in challenge_list:
                self._answers.append(self._client.answer_challenge(challenge, self._responses[challenge.chall.token]))

        # Request our final order and save the certificate if successful
        self._final_order = self._client.poll_and_finalize(self._order, deadline=deadline)
        self._certificate = self._final_order.fullchain_pem.encode()
        return self._certificate

    def revoke_certificate(self, reason: int = 0) -> None:
        """
        Attempts to revoke the existing certificate from the issuing ACME server.\n
        - :param `reason` [`int`]: the numeric reason for revocation identifier.\n
        - :return [`none`]:\n
        - :raises `errors.InvalidCertificate`: if this object does not contain a certificate.\n
        - :raises `acme.errors.ConflictError`: if the certificate is already revoked.\n\n

        ## Example\n
        ```python
        >>> client.revoke_certificate()
        ```
        """
        # Load the certificate crypto object and request revocation from the ACME server
        cert_obj = jose.ComparableX509(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.certificate))
        self._client.revoke(cert_obj, reason)

    def new_account(self) -> None:
        """
        Registers a new ACME account at the set ACME `_directory` URL. By running this method, you are agreeing to the
        ACME servers terms of use.\n
        - :return [`none`]: the account and account_key properties will be updated with the new account registration.\n
        - :raises `InvalidDirectory`: if this object does not contain a valid ACME _directory URL.\n
        - :raises `InvalidEmail`: if this object does not contain a valid _email address to use during registration.\n\n

        ## Example\n
        ```python
        >>> client.new_account()
        ```
        """
        # Generate a new RSA2048 account key
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=(default_backend()))
        self.account_key = jose.JWKRSA(key=rsa_key)

        # Initialize our ACME client object
        self._net = client.ClientNetwork(self.account_key, user_agent='simple_acme_dns/1.0.0')
        self._directory_obj = messages.Directory.from_json(self._net.get(self.directory).json())
        self._client = client.ClientV2(self._directory_obj, net=self._net)

        # Complete registration
        registration = messages.NewRegistration.from_data(email=self.email, terms_of_service_agreed=True)
        self.account = self._client.new_account(registration)

    def deactivate_account(self, delete: bool = True) -> None:
        """
        Deactivates the current account registration. This action is irreversible.\n
        - :param `delete` [`bool`]: indicate whether any associated account file on the local system should also be
        deleted after deactivation.\n
        - :return [`none`]:\n
        - :raises `InvalidAccount`: when account registration has not been set.\n\n

        ## Example\n
        ```python
        >>> client.deactivate_account()
        ```
        """
        # Tell the ACME server to deactivate this account
        self._client.deactivate_registration(self.account)

        # If this object contains a linked file path, and deletion is requested, delete the linked file
        if self.account_path and delete:
            # Delete the file if it's present
            try:
                pathlib.Path(self.account_path).unlink()
            except FileNotFoundError:
                pass

    def export_account(self, save_certificate: bool = True, save_private_key: bool = False) -> str:
        """
        Exports the object as a JSON string. This is useful when using a framework like Django and need to store account
        data as a string in the database.\n
        - :param `save_certificate` [`bool`]: indicate whether the certificate should also be stored in the
        JSON string.\n
        - :param `save_private_key` [`bool`]: indicate whether the private key should also be stored in the
        JSON string.\n
        - :return [`str`]: the current object encoded as a JSON string.\n
        - :raises `InvalidAccount`: when account registration has not been set.\n
        - :raises `InvalidDomain`: when no valid __domains__ are set.\n\n

        ## Example\n
        ```python
        >>> client.export_account(save_certificate=True, save_private_key=True)
        '{"account": {"body": {"key": {"n": "vtByzpW..."}}}}'
        ```
        """
        # Format our object into a serializable format
        acct_data = {
            'account': self.account.to_json(),
            'account_key': self.account_key.json_dumps(),
            'directory': self.directory,
            'domains': self.domains,
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
        Exports our object as a JSON file.\n
        - :param `path` [`str`]: the _directory path to save the account file. Defaults to current working _directory.\n
        - :param `name` [`str`]: the file name. Defaults to `account.json`.\n
        - :param `save_certificate` [`bool`]: indicate whether the certificate should also be stored in the JSON file.\n
        - :param `save_private_key` [`bool`]: indicate whether the private key should also be stored in the JSON file.\n
        - :return [`none`]: the file will be created at the specified path if an exception was not raised.\n
        - :raises `InvalidPath`: when the requested _directory path to export the account to does not exist.\n\n

        ## Example\n
        ```python
        >>> client.export_account_to_file(
        ...     path="/tmp/",
        ...     name="my_acme_account.json",
        ...     save_certificate=True,
        ...     save_private_key=True
        ... )
        ```
        """
        dir_path = pathlib.Path(path).absolute()

        # Ensure our path is an existing _directory, throw an error otherwise
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
        Loads an existing account from a JSON data string created by the `export_account()` method.\n
        - :param `json_data` [`str`]: the JSON account data string.\n
        - :return [`ACMEClient`]: the loaded ACMEClient object.\n\n

        ## Example\n
        ```python
        >>> client = simple_acme_dns.ACMEClient.load_account('{"account": {"body": {"key": {"n": "vtByzpW..."}}}}')
        ```
        """
        acct_data = json.loads(json_data)
        obj = ACMEClient()

        # Format the serialized data back into the object
        obj.directory = acct_data.get('directory', None)
        obj.domains = acct_data.get('domains', [])
        obj._certificate = acct_data.get('certificate', '').encode()
        obj._private_key = acct_data.get('private_key', '').encode()
        obj._email = acct_data['account']['body']['contact'][0].replace('mailto:', '')
        obj.account = messages.RegistrationResource.json_loads(json.dumps(acct_data['account']))
        obj.account_key = jose.JWKRSA.json_loads(acct_data['account_key'])

        # Re-initialize the ACME client and registration
        obj._net = client.ClientNetwork(obj.account_key, user_agent='simple_acme_dns/1.0.0')
        obj._directory = messages.Directory.from_json(obj._net.get(obj.directory).json())
        obj._client = client.ClientV2(obj._directory, net=obj._net)
        obj.account = obj._client.query_registration(obj.account)

        return obj

    @staticmethod
    def load_account_from_file(filepath: str) -> 'ACMEClient':
        """
        Loads an existing account from a JSON file created by the `export_account_to_file()` method.\n
        - :param `filepath` [`str`]: the file path to the account JSON file.\n
        - :return [`ACMEClient`]: the loaded ACMEClient object.\n
        - :raises `InvalidPath`: when the file path of the account JSON or key does not exist.\n

        ## Example\n
        ```python
        >>> client = simple_acme_dns.ACMEClient.load_account('/tmp/my_acme_account.json')
        ```
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
        take several minutes to complete, ensure you adjust the timeout value accordingly.\n
        - :param `timeout` [`int`]: the amount of time (in seconds) to continue trying to verify the TXT records.\n
        - :param `interval` [`float`]: the amount of time (in seconds) between DNS requests per domain.\n
        - :param `authoritative` [`bool`]: identify and use the authoritative nameserver for each domain instead of the
        objects `nameservers` property values.\n
        - :param `round_robin` [`bool`]: rotate between each nameserver instead of the default failover method.\n
        - :param `verbose` [`bool`]: print DNS answers to the console.\n
        - :return [`bool`]: indicates whether all the `domains` correctly return their verification token in
        their TXT record.\n\n

        ## Example\n
        ```python
        >>> client._nameservers = ["8.8.8.8", "1.1.1.1"]
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
        ```
        """
        # Variables
        verified = []
        resolvers = []
        timeout = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

        # Create a DNS resolver objects for each domain being verified.
        for rdomain, rtokens in self._verification_tokens.items():
            # Create a resolver for each token required for verification of this domain.
            for rtoken in rtokens:
                resolv = tools.DNSQuery(
                    rdomain,
                    rtype='TXT',
                    authoritative=authoritative,
                    nameservers=self._nameservers,
                    round_robin=round_robin
                )
                resolvers.append((rdomain, rtoken, resolv))

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
        Strips the wildcard portion of an domain (*.) if present.
        :param domain: the domain string to strip the wildcard from.
        :returns: the domain string without the wildcard portion.
        """
        # If wildcard domain, strip of the wildcard to validate domain
        return domain[2:] if domain[:2].startswith("*.") else domain

    @property
    def _challenges(self) -> dict:
        """
        Getter for the 'challenges' property. Returns current DNS challenges found in our current ACME order.
        :returns: a dict where the key is the domain name, and the value is a list of Challenge objects
        :raises errors.OrderNotFound: when this property is called before the 'order' object exists.
        """
        # Variables
        challs = {}

        # Do not allow this property to be called if an order has not been created beforehand.
        if not self._order:
            raise errors.OrderNotFound("Cannot get 'challenges' without an ACME order.")

        # Loop through each of our authorizations
        for auth in self._order.authorizations:
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
            raise errors.ChallengeUnavailable(msg.format(directory=(str(self._directory))))

        return challs

    @property
    def client(self) -> client.ClientV2:
        """
        Getter for the 'client' property. This checks that the ACME client is set up whenever it's referenced.
        :returns: the acme.client.ClientV2 object needed to interact with the ACME server
        :raises: InvalidAccount when no account registration is configured for this object
        """
        if not isinstance(self._client, client.ClientV2):
            msg = 'No account registration found. You must register a new account or load an existing account first.'
            raise errors.InvalidAccount(msg)

        return self._client

    @property
    def email(self) -> str:
        """
        Getter for the 'email' property. This checks that an email exists when it's referenced.
        :returns: a string representation of the email address
        :raises: InvalidEmail when no account _email is configured for this object.
        """
        if not self._email:
            msg = 'No account email found. You must set the _email value first.'
            raise errors.InvalidEmail(msg)

        return self._email

    @email.setter
    def email(self, value: str):
        """
        Setter for the 'email' property. This ensures an email address is valid before setting.
        :param value: the email address value to set.
        :returns: (none)
        """
        if not validators.email(value):
            msg = f"Value '{value}' is not a valid email address."
            raise errors.InvalidEmail(msg)

        self._email = value

    @property
    def verification_tokens(self) -> dict:
        """
        Getter for the 'verification_tokens' property. This checks that verification tokens already
        exist whenever they are referenced.
        :returns: a dict where the key is the domain name and the value is a list of tokens for that domain
        :raises: InvalidValidation when no verification tokens are issued for this object.
        """
        if not self._verification_tokens:
            msg = 'No verification tokens found. You must run request_verification_tokens() first.'
            raise errors.InvalidVerificationToken(msg)

        return self._verification_tokens

    @property
    def domains(self) -> list:
        """
        Getter for the 'domains' property. This checks that domains are already set whenever it's referenced.
        :returns: a list domains this object will request a certificate for
        :raises: InvalidDomain when no domains have been set
        """
        if not self._domains:
            msg = 'No domains found. You must set the domains value first.'
            raise errors.InvalidDomain(msg)

        return self._domains

    @domains.setter
    def domains(self, value) -> None:
        """
        Setter for the 'domains' property. This checks that the assigned domains value is a list of valid FQDNs.
        :param value: the value being requested for setting, this should be a list of domain names
        :returns: a list of valid domains
        :raises errors.InvalidDomain: when
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
    def certificate(self) -> bytes:
        """
        Getter for the 'certificate' property. This checks that a certificate is already set whenever it's referenced.
        :returns: a PEM encoded certificate bytes-string
        :raises: InvalidCertificate when no certificate exists for this object.
        """
        if not self._certificate:
            msg = 'No certificate found. You must load or request a certificate first.'
            raise errors.InvalidCertificate(msg)

        return self._certificate

    @certificate.setter
    def certificate(self, value: bytes) -> None:
        """
        Setter for the 'certificate' property. This ensures the set value is a bytes-string.
        :param value: the certificate value to set.
        :returns: (none)
        """
        # Convert string assignments to bytes
        if not isinstance(value, bytes):
            raise errors.InvalidCertificate("Certificate must be type 'bytes'.")

        self._certificate = value

    @property
    def private_key(self) -> bytes:
        """
        Getter for the 'private_key' property. This checks that a private_key is already set whenever it's referenced.
        :returns: a PEM encoded private_key bytes-string
        :raises: errors.InvalidPrivateKey when no private_key exists for this object.
        """
        if not self._private_key:
            msg = 'No private_key found. You must load or request a private_key first.'
            raise errors.InvalidPrivateKey(msg)

        return self._private_key

    @private_key.setter
    def private_key(self, value: bytes) -> None:
        """
        Setter for the 'private_key' property. This ensures the set value is a bytes-string.
        :param value: the private_key value to set.
        :returns: (none)
        """
        # Convert string assignments to bytes
        if not isinstance(value, bytes):
            raise errors.InvalidCertificate("Private key must be type 'bytes'.")

        self._private_key = value
