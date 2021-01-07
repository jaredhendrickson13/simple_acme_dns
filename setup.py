# Copyright 2021 Jared Hendrickson
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

from setuptools import setup


# Open and read our README markdown for the long description value
def read_me():
    with open('README.md') as f:
        return f.read()


# Open, read and parse our requirements text to an array for the install_requires value
def requirements():
    with open('requirements.txt') as f:
        return list(filter(None, f.read().split("\n")))


# Set our setup parameters
setup(
    name='simple_acme_dns',
    author='Jared Hendrickson',
    author_email='jaredhendrickson13@gmail.com',
    url="https://github.com/jaredhendrickson13/simple_acme_dns",
    license="Apache-2.0",
    description="A Python ACME client for the DNS-01 challenge",
    long_description=read_me(),
    long_description_content_type="text/markdown",
    version="1.0.2",
    packages=["simple_acme_dns", "simple_acme_dns.tools", "simple_acme_dns.errors"],
    install_requires=requirements(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6'
)
