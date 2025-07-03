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

import simple_acme_dns

# Create a client object to interface with the ACME server. In this example, the Let's Encrypt staging environment.
client = simple_acme_dns.ACMEClient(
    domains=["test.example.com"],
    email="user@example.com",
    directory="https://acme-staging-v02.api.letsencrypt.org/directory",
    nameservers=[
        "8.8.8.8",
        "1.1.1.1",
    ],  # Set the nameservers to query when checking DNS propagation
    new_account=True,  # Register a new ACME account upon creation of our object
    generate_csr=True,  # Generate a new private key and CSR upon creation of our object
)

# Request the verification token for our DOMAIN. Print the challenge FQDN and it's corresponding token.
for domain, tokens in client.request_verification_tokens().items():
    print(f"{ domain } -> {tokens}")

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
