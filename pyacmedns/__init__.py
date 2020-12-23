import OpenSSL
import datetime
import josepy as jose
import json
import pathlib
import time
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


class ACMEClient:
    """A basic ACME client object to interface with a CA using the ACME DNS-01 challenge"""

    def __init__(
            self, domains=None, email=None, directory=None, nameservers=None, new_account=False, generate_csr=False
    ):
        """
        Initializes our ACMEClient object with defaults values or input parameters.
        :param domains: (list) FQDNs to list in the certificate (SANS).
        :param email: (str) a valid email address to register new ACME accounts with.
        :param directory: (str) the ACME directory URL.
        :param nameservers: (list) nameservers to use when querying DNS. If none, the system's default will be used.
        :param new_account: (bool) automatically register a new account upon object creation. A `directory` and `email`
        value will be required if True.
        :param generate_csr: (bool) generate a new private key and CSR upon object creation. A `domains` value will be
        required if True.
        """
        self.DNS_LABEL = '_acme-challenge'
        self.domains = domains if domains else []
        self.email = email
        self.directory = directory
        self.certificate = ''.encode()
        self.private_key = ''.encode()
        self.csr = ''.encode()
        self.verification_tokens = []
        self.account_key = None
        self.account = None
        self.account_path = None
        self.nameservers = nameservers
        self.__private_key__ = None
        self.__client__ = None
        self.__net__ = None
        self.__directory__ = None
        self.__order__ = None
        self.__final_order__ = None
        self.__verification_tokens__ = []
        self.__responses__ = []
        self.__challenges__ = []
        self.__answers__ = []

        # Automatically create a new account if requested
        if new_account:
            self.new_account()
        # Automatically create a new private key and CSR
        if generate_csr:
            self.generate_private_key_and_csr()

    def generate_csr(self):
        """
        Generates a new CSR using the object's `domains` and `private_key` values.
        :return: (bytes) the encoded CSR PEM data string. This method will update the `csr` property of the object
        with the same value.
        :raises: InvalidDomain when no valid `domains` are set.
        :raises: InvalidPrivateKey when no `private_key` exists for this object.
        """
        self.__validate_domains__()
        self.__validate_private_key__()
        self.csr = crypto_util.make_csr(self.private_key, self.domains)
        return self.csr

    def generate_private_key(self, key_type='ec256'):
        """
        Generates a new RSA or EC private key.
        :param key_type: (str) the requested `private_key` type ['ec256', 'ec384', 'rsa2048', 'rsa4098']
        :return: (bytes) the encoded private key PEM data string. This method will update the `private_key` property of
        the object with the same value.
        :raises: InvalidKeyType when an unknown/unsupported `key_type` is requested
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
        # Generate a RSA4098 private key
        elif key_type == 'rsa4098':
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
            self.private_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        # Otherwise, the requested key type is not supported. Throw an error
        else:
            options = ['ec256', 'ec384', 'rsa2048', 'rsa4098']
            msg = "Invalid private key rtype '{key_type}'. Options {options}".format(key_type=key_type, options=options)
            raise errors.InvalidKeyType(msg)
        return self.private_key

    def generate_private_key_and_csr(self, key_type='ec256'):
        """
        Generates a new private key and CSR.
        :param key_type: (str) the requested `private_key` type ['ec256', 'ec384', 'rsa2048', 'rsa4098']
        :return: (tuple) first value contains the key, the second value contains the CSR. This method will update
        the `private_key` and `csr` properties of this object with the same values.
        """
        self.generate_private_key(key_type=key_type)
        self.generate_csr()
        return self.private_key, self.csr

    def request_verification_tokens(self):
        """
        Requests verification tokens from the ACME server for each `domains` value. These tokens must be uploaded to as
        a DNS TXT record for each corresponding domain to complete verification.
        :return: (list) a list of tuples containing the challenge FQDN and it's corresponding verification token.
        :raises: InvalidAccount when account registration has not been set.
        """
        self.__validate_registration__()
        self.__responses__ = []
        self.__verification_tokens__ = []
        self.__order__ = self.__client__.new_order(self.csr)
        self.__challenges__ = self.__verify_challenge__()

        # Loop through each of our challenges and extract the response and verification token from each
        for i, c in enumerate(self.__challenges__):
            response, validation = c.response_and_validation(self.__client__.net.key)
            self.__responses__.append(response)
            self.__verification_tokens__.append(validation)

        return self.__format_verification_tokens__()

    def request_certificate(self, wait=0, timeout=90):
        """
        Requests a final verification answer from the ACME server and requests the certificate if verification was
        successful.
        :param: wait: (int) amount of time (in seconds) to wait before requesting a challenge answer from the server.
        This is only necessary if you are not using the `check_dns_propagation()` method to verify the DNS records
        exist and would rather wait a specific amount of time.
        :return: (bytes) the PEM encoded certificate. This method will update the `certificate` and `csr` property of
        this object with the same value.
        :raises: InvalidAccount when account registration has not been set.
        """
        self.__validate_verification_tokens__()
        time.sleep(wait)
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

        # For each challenge, request an answer.
        for i, c in enumerate(self.__challenges__):
            self.__answers__.append(self.__client__.answer_challenge(c, self.__responses__[i]))

        # Request our final order and save the certificate if successful
        self.__final_order__ = self.__client__.poll_and_finalize(self.__order__, deadline=deadline)
        self.certificate = self.__final_order__.fullchain_pem.encode()
        return self.certificate

    def revoke_certificate(self, reason=0):
        """
        Attempts to revoke the existing certificate from the issuing ACME server.
        :param reason: (int) the numeric reason for revocation identifier.
        :return: (none)
        :raises: InvalidCertificate if this object does not contain a certificate.
        :raises: acme.errors.ConflictError if the certificate is already revoked.
        """
        self.__validate_certificate__()

        # Load the certificate crypto object and request revocation from the ACME server
        cert_obj = jose.ComparableX509(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.certificate))
        self.__client__.revoke(cert_obj, reason)

    def new_account(self):
        """
        Registers a new ACME account at the set ACME `directory` URL. By running this method, you are agreeing to the
        ACME servers terms of use.
        :return: (none) the account and account_key properties will be updated with the new account registration.
        :raises: InvalidDirectory if this object does not contain a valid ACME directory URL.
        :raises: InvalidEmail if this object does not contain a valid email address to use during registration.
        """
        self.__validate_directory__()
        self.__validate_email__()

        # Generate a new RSA2048 account key
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=(default_backend()))
        self.account_key = jose.JWKRSA(key=rsa_key)

        # Initialize our ACME client object
        self.__net__ = client.ClientNetwork(self.account_key, user_agent='pyacmedns/1.0.0')
        self.__directory__ = messages.Directory.from_json(self.__net__.get(self.directory).json())
        self.__client__ = client.ClientV2(self.__directory__, net=self.__net__)

        # Complete registration
        registration = messages.NewRegistration.from_data(email=self.email, terms_of_service_agreed=True)
        self.account = self.__client__.new_account(registration)

    def deactivate_account(self, delete=True):
        """
        Deactivates the current account registration. This is irreversible.
        :param delete: (bool) indicate whether any associated account file on the local system should also be deleted.
        :return: (none)
        :raises: InvalidAccount when account registration has not been set.
        """
        self.__validate_registration__()

        # Tell the ACME server to deactivate this account
        self.__client__.deactivate_registration(self.account)

        # If this object contains a linked file path, and deletion is requested, delete the linked file
        if self.account_path and delete:
            pathlib.Path(self.account_path).unlink(missing_ok=True)

    def export_account(self, save_certificate=True, save_private_key=False):
        """
        Exports the object as a JSON string. This is useful when using a framework like Django and need to store account
        data as a string in the database.
        :param save_certificate: (bool) indicate whether the certificate should also be stored in the JSON string.
        :param save_private_key: (bool) indicate whether the private key should also be stored in the JSON string.
        :return: (str) the current object encoded as a JSON string.
        :raises: InvalidAccount when account registration has not been set
        :raises: InvalidDomain when no valid domains are set
        """
        self.__validate_registration__()
        self.__validate_domains__()

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

    def export_account_to_file(self, path='.', name='account.json', save_certificate=True, save_private_key=False):
        """
        Exports our object as a JSON file.
        :param path: (str) the directory path to save the account file. Defaults to current working directory.
        :param name: (str) the file name. Defaults to `account.json`.
        :param save_certificate: (bool) indicate whether the certificate should also be stored in the JSON file.
        :param save_private_key: (bool) indicate whether the private key should also be stored in the JSON file.
        :return: (none) the file will be created at the specified path if an exception was not raised.
        :raises: InvalidPath when the requested directory path to export the account to does not exist.
        """
        self.__validate_registration__()
        self.__validate_domains__()
        dir_path = pathlib.Path(path).absolute()

        # Ensure our path is an existing directory, throw an error otherwise
        if dir_path.is_dir():
            # Open the file and write our JSON content
            with open(str(dir_path.joinpath(name)), 'w') as (wa):
                wa.write(self.export_account(save_certificate, save_private_key))
                self.account_path = str(dir_path.joinpath(name))
        else:
            msg = "Directory at '{path}' does not exist.".format(path=path)
            raise errors.InvalidPath(msg)

    @staticmethod
    def load_account(json_data):
        """
        Loads an existing account from a JSON data string.
        :param json_data: (str) the JSON account data string.
        :return: (ACMEClient) the loaded ACMEClient object.
        """
        acct_data = json.loads(json_data)
        obj = ACMEClient()

        # Format the serialized data back into the object
        obj.directory = acct_data.get('directory', None)
        obj.domains = acct_data.get('domains', [])
        obj.certificate = acct_data.get('certificate', '').encode()
        obj.private_key = acct_data.get('private_key', '').encode()
        obj.email = acct_data['account']['body']['contact'][0].replace('mailto:', '')
        obj.account = messages.RegistrationResource.json_loads(json.dumps(acct_data['account']))
        obj.account_key = jose.JWKRSA.json_loads(acct_data['account_key'])

        return obj

    @staticmethod
    def load_account_from_file(filepath):
        """
        Loads an existing account from a JSON file.
        :param filepath: (str) the file path to the account JSON file.
        :return: (ACMEClient) the loaded ACMEClient object.
        :raises: InvalidPath when the file path of the account JSON or key does not exist.
        """
        filepath = pathlib.Path(filepath).absolute()

        # Ensure our file exists, throw an error otherwise
        if filepath.exists():
            # Open our file and read it's contents.
            with open(filepath, 'r') as (rj):
                json_data = rj.read()

            # Load contents into a new object.
            obj = ACMEClient.load_account(json_data)
            obj.account_path = filepath
        else:
            raise errors.InvalidPath("No JSON account file found at '{path}'".format(path=(str(filepath))))

        # Re-initialize the ACME client and registration
        obj.__net__ = client.ClientNetwork(obj.account_key, user_agent='pyacmedns/1.0.0')
        obj.__directory__ = messages.Directory.from_json(obj.__net__.get(obj.directory).json())
        obj.__client__ = client.ClientV2(obj.__directory__, net=obj.__net__)
        obj.account = obj.__client__.query_registration(obj.account)

        return obj

    def check_dns_propagation(self, timeout=300, interval=2, authoritative=False, round_robin=True, verbose=False):
        """
        Check's each of our domain's TXT record until the value matches it's verification token or until the timeout is
        reached. This method should be executed before executing the `request_certificates()` method.
        :param timeout: (int) the amount of time (in seconds) to continue trying to verify the TXT records.
        :param interval: (float) the amount of time (in seconds) between DNS requests per domain.
        :param authoritative: (bool) identify and use the authoritative nameserver for each domain instead of the
        objects `nameservers` property values.
        :param round_robin: (bool) rotate between each nameserver instead of the default failover method.
        :param verbose: (bool) print DNS answers to the console.
        :return: (bool) indicates whether or not all of the `domains` correctly return their verification token in their
        TXT record.
        """
        self.__validate_verification_tokens__()
        verified = []
        resolvers = []
        timeout = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

        # Create a DNS resolver object for each domain being verified
        for rdomain, rtoken in self.verification_tokens:
            r = tools.DNSQuery(
                rdomain,
                rtype='TXT',
                authoritative=authoritative,
                nameservers=self.nameservers,
                round_robin=round_robin
            )
            resolvers.append((rdomain, rtoken, r))

        # Loop until we have exceeded our timeout value
        while datetime.datetime.now() < timeout:
            # Loop through each domain being verified
            for domain, token, resolver in resolvers:
                # Only try to verify the domain if it has not already been verified
                if domain not in verified:
                    resolver.resolve()
                    # Save this domain as verified if our token was found in the TXT record values
                    if token in resolver.values:
                        verified.append(domain)
                    # If verbose mode is enabled, print the results to the console
                    if verbose:
                        msg = "Token '{token}' for '{domain}' {action} in {values} via {ns}".format(
                            token=token,
                            domain=domain,
                            action=('found' if domain in verified else 'not found'),
                            values=resolver.values,
                            ns=resolver.last_nameserver
                        )
                        print(msg)

            # If all our domains have been verified
            if len(verified) == len(self.verification_tokens):
                return True

            # Avoid flooding the DNS server(s)
            time.sleep(interval)

        return False

    def __verify_challenge__(self):
        """
        Checks that the DNS-01 challenge is supported by the ACME server and initializes the challenge. This is an
        internal method and is not intended for use otherwise.
        :return: (list) a list of acme.challenges.ChallengeBody objects
        :raises: ChallengeUnavailable when the specified ACME server does not support the DNS-01 challenge
        """
        self.__challenges__ = []
        authz_list = self.__order__.authorizations

        # Loop through each of our authorizations
        for authz in authz_list:
            # Loop through each authorization's available challenges
            for i in authz.body.challenges:
                # Add the DNS-01 challenge if it is found
                if isinstance(i.chall, challenges.DNS01):
                    self.__challenges__.append(i)

        # If no challenges were found, throw an error
        if not self.__challenges__:
            msg = "ACME server at '{directory}' does not support DNS-01 challenge."
            raise errors.ChallengeUnavailable(msg.format(directory=(str(self.directory))))

        return self.__challenges__

    def __validate_registration__(self):
        """
        Checks that our client is initialized with proper account registration.
        :return: (none)
        :raises: InvalidAccount when no account registration is configured for this object
        """
        if type(self.__client__) != client.ClientV2:
            msg = 'No account registration found. You must register a new account or load an existing account first.'
            raise errors.InvalidAccount(msg)

    def __validate_email__(self):
        """
        Checks that our client is initialized with proper account email.
        :return: (none)
        :raises: InvalidEmail when no account email is configured for this object.
        """
        if not self.email:
            msg = 'No account email found. You must set the email value first.'
            raise errors.InvalidEmail(msg)

    def __validate_verification_tokens__(self):
        """
        Checks that our client object has valid verification tokens.
        :return: (none)
        :raises: InvalidValidation when no verification tokens are issued for this object.
        """
        if not self.__verification_tokens__:
            msg = 'No verification tokens found. You must run request_verification_tokens() first.'
            raise errors.InvalidVerificationToken(msg)

    def __validate_domains__(self):
        """
        Checks that our client is initialized with valid domain names.
        :return: (none)
        :raises: InvalidDomain when no domains are specified, domains is not list, or domain is not RFC2181 compliant.
        """
        if not self.domains:
            msg = 'No domains found. You must set a domains value first.'
            raise errors.InvalidDomain(msg)
        if type(self.domains) != list:
            msg = "Domains must be rtype 'list'."
            raise errors.InvalidDomain(msg)
        for domain in self.domains:
            if not validators.domain(domain):
                msg = "Invalid domain name '{domain}'. Domain name must adhere to RFC2181.".format(domain=domain)
                raise errors.InvalidDomain(msg)

    def __validate_directory__(self):
        """
        Checks that our client object has a valid ACME server directory URL.
        :return: (none)
        :raises: InvalidACMEDirectoryURL when no directory URL is set.
        """
        if not self.directory:
            msg = 'No ACME server directory URL. You must set a directory value first.'
            raise errors.InvalidACMEDirectoryURL(msg)

    def __validate_certificate__(self):
        """
        Checks that our client object holds an issued certificate.
        :return: (none)
        :raises: InvalidCertificate when no certificate exists for this object.
        """
        if not self.certificate:
            msg = 'No certificate found. You must load or request a certificate first.'
            raise errors.InvalidCertificate(msg)

    def __validate_private_key__(self):
        """
        Checks that our client is initialized with a valid private key.
        :return: (none)
        :raises: InvalidPrivateKey when no private exists for this object.
        """
        if not self.private_key:
            msg = 'No private found. You must generate a private key first.'
            raise errors.InvalidPrivateKey(msg)

    def __format_verification_tokens__(self):
        """
        Formats the FQDNs the ACME server expects and their corresponding verification token to upload to DNS.
        :return: (list) a list of tuples. First value is the FQDN, second value is the verification token.
        """
        self.__validate_domains__()
        self.__validate_verification_tokens__()
        groupings = []

        # Loop through each domain and group it with it's corresponding verification token
        for i, domain in enumerate(self.domains):
            groupings.append((self.DNS_LABEL + '.' + domain, self.__verification_tokens__[i]))

        self.verification_tokens = groupings
        return groupings
