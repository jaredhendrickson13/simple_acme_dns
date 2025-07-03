# simple_acme_dns

[![Quality](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/quality.yml/badge.svg)](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/quality.yml)
[![Release](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/release.yml/badge.svg)](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/release.yml)
[![CodeQL](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/codeql.yml/badge.svg)](https://github.com/jaredhendrickson13/simple_acme_dns/actions/workflows/codeql.yml)

**simple_acme_dns** is a Python ACME client wrapper specifically tailored to the DNS-01 challenge. This makes it easy to manage ACME 
certificates and accounts entirely within Python, without the need for bloated external tools like `certbot`. Although this module is intended for use
with Let's Encrypt, it will support any CA utilizing the ACME v2 protocol.

### Key Features

- **Full Certificate Lifecycle:** Manage certificate generation, renewal, and revocation directly within your Python application.
- **Built-in Key & CSR Generation:** Create RSA and EC private keys, and CSRs programmatically; or use your own!
- **ACME profiles:** Supports [ACME profile](https://letsencrypt.org/docs/profiles/) selection, allowing you to specify the desired profile for your certificates. 
- **Portable ACME Accounts:** Easily export and import ACME account data for flexible storage and reuse.
- **Developer-Driven DNS Integration:** No bundled DNS providers; designed for you to implement custom DNS updates with maximum flexibility.
- **DNS Propagation Checks:** Tools to verify DNS TXT record propagation, ensuring smooth challenge completion.
- **Lightweight & Minimal Dependencies:** A lean design with few dependencies, ideal for embedded use.

### Installation
```commandline
pip install simple_acme_dns
```

### Documentation
Refer to the [simple_acme_dns documentation pages](https://jaredhendrickson13.github.io/simple_acme_dns/) for the most 
up-to-date documentation. Example scripts can also be found on 
[GitHub](https://github.com/jaredhendrickson13/simple_acme_dns/tree/master/examples).
