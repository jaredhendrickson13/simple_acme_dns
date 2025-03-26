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
"""Sets build parameters for the simple_acme_dns module."""
from setuptools import setup


# Open and read our README markdown for the long description value
def read_readme():
    """Opens and reads the main README.md file for this repo."""
    with open('README.md', 'r', encoding='utf-8') as readme_file:
        return readme_file.read()


# Open, read and parse our requirements text to an array for the install_requires value
def read_requirements():
    """Opens and read the requirements.txt file for this repo."""
    with open('requirements.txt', 'r', encoding='utf-8') as requirements_file:
        return list(filter(None, requirements_file.read().split("\n")))


# Set our setup parameters
setup(
    name='simple_acme_dns',
    author='Jared Hendrickson',
    author_email='github@jaredhendrickson.com',
    url="https://github.com/jaredhendrickson13/simple_acme_dns",
    license="Apache-2.0",
    description="A Python ACME client for the DNS-01 challenge",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    version="3.3.0",
    packages=["simple_acme_dns", "simple_acme_dns.tools", "simple_acme_dns.errors"],
    install_requires=read_requirements(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.9'
)
