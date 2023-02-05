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

import simple_acme_dns
import sys

verbose = True if "--verbose" in sys.argv else False

# Create a client object to interface with the ACME server. In this example, the Let's Encrypt staging environment.
client = simple_acme_dns.ACMEClient(
    domains=["test.jaredhendrickson.com", "test2.jaredhendrickson.com"],
    email="user@jaredhendrickson.com",
    directory="https://acme-staging-v02.api.letsencrypt.org/directory",
    nameservers=["8.8.8.8", "1.1.1.1"]
)

# Manually enroll a new account
client.new_account()

# Create a new RSA private key and CSR
client.generate_private_key_and_csr(key_type="rsa4096")

# Request the verification token for our domains. Print each challenge FQDN and it's corresponding token.
for domain, token in client.request_verification_tokens():
    print("{domain} --> {token}".format(domain=domain, token=token))

# [ !!! ADD YOUR CODE TO UPLOAD THE TOKEN TO YOUR DNS SERVER HERE; OR UPLOAD THE TOKEN MANUALLY !!! ]

# Start waiting for DNS propagation before requesting the certificate
# Keep checking DNS for the verification token for 1200 seconds (10 minutes) before giving up.
# If a DNS query returns the matching verification token, request the certificate. Otherwise, deactivate the account.
if client.check_dns_propagation(timeout=1200):
    client.request_certificate()
    print(client.certificate.decode())
    print(client.private_key.decode())
else:
    client.deactivate_account()
    print("Failed to issue certificate for " + str(client.domains))
    exit(1)

# Revoke the certificate
client.revoke_certificate()

# Renew the certificate with a new private key
client.generate_private_key_and_csr(key_type="rsa2048")

# Request a new verification token for our domains. Print each challenge FQDN and it's corresponding token.
for domain, token in client.request_verification_tokens():
    print("{domain} --> {token}".format(domain=domain, token=token))

# [ !!! ADD YOUR CODE TO UPLOAD THE NEW TOKENs TO YOUR DNS SERVER HERE; OR UPLOAD THE TOKEN MANUALLY !!! ]

# Start waiting for DNS propagation before requesting the certificate again
# Keep checking DNS for the verification token for 1200 seconds (10 minutes) before giving up.
# If a DNS query returns the matching verification token, request the certificate. Otherwise, deactivate the account.
if client.check_dns_propagation(timeout=1200, verbose=verbose):
    client.request_certificate()
    print(client.certificate.decode())
    print(client.private_key.decode())
else:
    client.deactivate_account()
    print("Failed to issue certificate for " + str(client.domains))
    exit(1)