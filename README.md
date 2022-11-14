simple_acme_dns
================
[![Coverage](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/coverage.yml/badge.svg)](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/coverage.yml)
[![PyPI](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/pypi.yml/badge.svg)](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/pypi.yml)
[![PyLint](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/pylint.yml/badge.svg)](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/pylint.yml)
[![CodeQL](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/codeql.yml/badge.svg)](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/codeql.yml)

**simple_acme_dns** is a pure-Python ACME client specifically tailored to the DNS-01 challenge. This makes it easy to manage ACME 
certificates and accounts without the need for an external tool like `certbot`. Although this module is intended for use
with Let's Encrypt, it will support any CA utilizing the ACME v2 protocol.

Sub-modules
-----------
* simple_acme_dns.errors
* simple_acme_dns.tools

Classes
-------

`ACMEClient(domains=None, email=None, directory=None, nameservers=None, new_account=False, generate_csr=False)`
:   A basic ACME client object to interface with a CA using the ACME DNS-01 challenge.
    
- :var `certificate` [`bytes`]: the PEM formatted certificate. This value is populated after successfully running
the `request_certificate()` methood.

- :var `private_key` [`bytes`]: the PEM formatted private key. This value is populated after successfully running
the `generate_private_key()` method.

- :var `csr` [`bytes`]: the PEM formatted certificate signing request. This value is populated after successfully
running the `generate_csr()` method.

- :param `domains` [`list`]: FQDNs to list in the certificate (SANS).

- :param `email` [`str`]: a valid email address to register new ACME accounts with.

- :param `directory` [`str`]: the ACME directory URL.

- :param `nameservers` [`list`]: nameservers to use when querying DNS. Defaults to system nameservers.

- :param `new_account` [`bool`]: automatically register a new account upon object creation. A `directory` and
`email` value will be required if True.

- :param `generate_csr` [`bool`]: generate a new private key and CSR upon object creation. A `domains` value
will be required if True.



#### Example:

```python
>>> import simple_acme_dns
>>> client = simple_acme_dns.ACMEClient(
...     domains=["test1.example.com", "test2.example.com"],
...     email="example@example.com",
...     directory="https://acme-staging-v02.api.letsencrypt.org/directory",
...     nameservers=["8.8.8.8", "1.1.1.1"],
...     new_account=True,
...     generate_csr=True
... )
```
---
### Static methods

`load_account(json_data)`
:   Loads an existing account from a JSON data string created by the `export_account()` method.
    
- :param `json_data` [`str`]: the JSON account data string.

- :return [`ACMEClient`]: the loaded ACMEClient object.



#### Example

```python
>>> client = simple_acme_dns.ACMEClient.load_account('{"account": {"body": {"key": {"n": "vtByzpW..."}}}}')
```
---
`load_account_from_file(filepath)`
:   Loads an existing account from a JSON file created by the `export_account_to_file()` method.
    
- :param `filepath` [`str`]: the file path to the account JSON file.

- :return [`ACMEClient`]: the loaded ACMEClient object.

- :raises `InvalidPath`: when the file path of the account JSON or key does not exist.


#### Example

```python
>>> client = simple_acme_dns.ACMEClient.load_account('/tmp/my_acme_account.json')
```
---
### Methods

`check_dns_propagation(self, timeout=300, interval=2, authoritative=False, round_robin=True, verbose=False)`
:   Check's each of our domain's TXT record until the value matches it's verification token or until the timeout is
    reached. This method should be executed before executing the `request_certificates()` method. This method can
    take several minutes to complete, ensure you adjust the timeout value accordingly.
    
- :param `timeout` [`int`]: the amount of time (in seconds) to continue trying to verify the TXT records.

- :param `interval` [`float`]: the amount of time (in seconds) between DNS requests per domain.

- :param `authoritative` [`bool`]: identify and use the authoritative nameserver for each domain instead of the
objects `nameservers` property values.

- :param `round_robin` [`bool`]: rotate between each nameserver instead of the default failover method.

- :param `verbose` [`bool`]: print DNS answers to the console.

- :return [`bool`]: indicates whether or not all of the `domains` correctly return their verification token in
their TXT record.



#### Example

```python
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
```
---
`deactivate_account(self, delete=True)`
:   Deactivates the current account registration. This action is irreversible.
    
- :param `delete` [`bool`]: indicate whether any associated account file on the local system should also be
deleted after deactivation.

- :return [`none`]:

- :raises `InvalidAccount`: when account registration has not been set.



#### Example

```python
>>> client.deactivate_account()
```
---
`export_account(self, save_certificate=True, save_private_key=False)`
:   Exports the object as a JSON string. This is useful when using a framework like Django and need to store account
    data as a string in the database.
    
- :param `save_certificate` [`bool`]: indicate whether the certificate should also be stored in the
JSON string.

- :param `save_private_key` [`bool`]: indicate whether the private key should also be stored in the
JSON string.

- :return [`str`]: the current object encoded as a JSON string.

- :raises `InvalidAccount`: when account registration has not been set.

- :raises `InvalidDomain`: when no valid domains are set.



#### Example

```python
>>> client.export_account(save_certificate=True, save_private_key=True)
'{"account": {"body": {"key": {"n": "vtByzpW..."}}}}'
```
---
`export_account_to_file(self, path='.', name='account.json', save_certificate=True, save_private_key=False)`
:   Exports our object as a JSON file.
    
- :param `path` [`str`]: the directory path to save the account file. Defaults to current working directory.

- :param `name` [`str`]: the file name. Defaults to `account.json`.

- :param `save_certificate` [`bool`]: indicate whether the certificate should also be stored in the JSON file.

- :param `save_private_key` [`bool`]: indicate whether the private key should also be stored in the JSON file.

- :return [`none`]: the file will be created at the specified path if an exception was not raised.

- :raises `InvalidPath`: when the requested directory path to export the account to does not exist.



#### Example

```python
>>> client.export_account_to_file(
...     path="/tmp/",
...     name="my_acme_account.json",
...     save_certificate=True,
...     save_private_key=True
... )
```
---
`generate_csr(self)`
:   Generates a new CSR using the object's `domains` and `private_key` values.
    
- :return [`bytes`]: the encoded CSR PEM data string. This method will update the `csr` property of the object
with the same value.

- :raises `InvalidDomain`: when no valid `domains` are set.

- :raises `InvalidPrivateKey`: when no `private_key` exists for this object.



#### Example

```python
>>> client.generate_csr()
b'-----BEGIN CERTIFICATE REQUEST-----\nMIHxMIGZAgECMAAwWTATBgckjkn...'
```
---
`generate_private_key(self, key_type='ec256')`
:   Generates a new RSA or EC private key.
    
- :param `key_type` [`str`]: the requested `private_key` type. Options are: [`ec256`, `ec384`, `rsa2048`,
`rsa4096`]

- :return [`bytes`]: the encoded private key PEM data string. This method will update the `private_key` property
 of the object with the same value.

- :raises `InvalidKeyType`: when an unknown/unsupported `key_type` is requested



#### Example

```python
>>> client.generate_private_key(key_type="ec384")
b'-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAZRFNLcQdVJmLh42p8F4D92...'
```
---
`generate_private_key_and_csr(self, key_type='ec256')`
:   Generates a new private key and CSR.
    
- :param `key_type` [`str`]: the requested `private_key` type. Options are: [`ec256`, `ec384`, `rsa2048`,
`rsa4096`]

- :return [`tuple`]: first value contains the key, the second value contains the CSR. This method will update
the `private_key` and `csr` properties of this object with the same values.



#### Example

```python
>>> client.generate_private_key_and_csr(key_type="rsa2048")
(b'-----BEGIN PRIVATE KEY-----\nMIIEvAIBA...', b'-----BEGIN CERTIFICATE REQUEST-----\nMIHxM...')
```
---
`new_account(self)`
:   Registers a new ACME account at the set ACME `directory` URL. By running this method, you are agreeing to the
    ACME servers terms of use.
    
- :return [`none`]: the account and account_key properties will be updated with the new account registration.

- :raises `InvalidDirectory`: if this object does not contain a valid ACME directory URL.

- :raises `InvalidEmail`: if this object does not contain a valid email address to use during registration.



#### Example

```python
>>> client.new_account()
```
---
`request_certificate(self, wait=0, timeout=90)`
:   Requests a final verification answer from the ACME server and requests the certificate if verification was
    successful. If you request the certificate before DNS has propagated and verification fails, you must start
    the verification process over entirely by requesting new verification tokens.
    
- :param `wait` [`int`]: amount of time (in seconds) to wait before requesting a challenge answer from the
server. This is only necessary if you are not using the `check_dns_propagation()` method to verify the DNS
records exist and would rather wait a specific amount of time.

- :return [`bytes`]: the PEM encoded certificate. This method will update the `certificate` and `csr` property
of this object with the same value.

- :raises `InvalidAccount`:  when account registration has not been set.



#### Example

```python
>>> client.request_certificate()
b'-----BEGIN CERTIFICATE-----\nMIIEfzCCA2egAwI...
```
---
`request_verification_tokens(self)`
:   Requests verification tokens from the ACME server for each `domains` value. These tokens must be uploaded as
    a DNS TXT record for each corresponding domain to complete verification.
    
- :return [`list`]: a list of tuples containing the challenge FQDN and it's corresponding verification token.

- :raises `InvalidAccount`: when account registration has not been set.



#### Example

```python
>>> client.request_verification_tokens()
[
    ('_acme-challenge.test1.example.com', 'moY32lkdsZ3VWHM1mdM...'),
    ('_acme-challenge.test2.example.com', 'asldfkjslweietj23_b...')
]
```
---
`revoke_certificate(self, reason=0)`
:   Attempts to revoke the existing certificate from the issuing ACME server.
    
- :param `reason` [`int`]: the numeric reason for revocation identifier.

- :return [`none`]:

- :raises `InvalidCertificate`: if this object does not contain a certificate.

- :raises `acme.errors.ConflictError`: if the certificate is already revoked.



#### Example

```python
>>> client.revoke_certificate()
```
