"""Unit tests and testing tools for the simple_acme_dns package."""

import os
import random

BASE_DOMAIN = "testing.jaredhendrickson.com"
TEST_DOMAINS = [f"{random.randint(10000, 99999)}.simple-acme-dns.{BASE_DOMAIN}"]
TEST_EMAIL = f"simple-acme-dns@{BASE_DOMAIN}"
TEST_DIRECTORY = os.environ.get(
    "ACME_DIRECTORY", "https://acme-staging-v02.api.letsencrypt.org/directory"
)
TEST_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]
