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
"""DNS tools to assist ACME verification."""
import dns.resolver


class DNSQuery:
    """A basic class to make DNS queries"""

    def __init__(
        self,
        domain: str,
        rtype: str = "A",
        nameservers: list = None,
        authoritative: bool = False,
        round_robin: bool = False
    ) -> None:
        """
        Initializes and executes our DNS query.\n
        - :param `domain` [`str`]: the FQDN to query.\n
        - :param `rtype` [`str`]: the DNS request type (e.g. `A`, `TXT`, `CNAME`, etc.).\n
        - :param `nameservers` [`list`]: nameservers to query when making DNS requests.\n
        - :param `authoritative` [`bool`]: indicate whether the authoritative nameserver for the domain should be
        identified and used. Once identified, the `nameservers` will be replaced with the authoritative nameserver.\n
        - :param `round_robin` [`bool`]: rotate between each nameserver instead of the default failover method.\n
        """
        self.round_robin = round_robin
        self.type = rtype.upper()
        self.domain = domain
        self.nameservers = nameservers if nameservers else dns.resolver.Resolver().nameservers
        self.nameservers = self.__get_authoritative_nameservers__() if authoritative else self.nameservers
        self.values = []
        self.answers = []
        self.last_nameserver = ""

    def resolve(self) -> list:
        """
        Queries the nameservers with our configured object values.\n
        - :return [`list`]: answer values from the request. The list will be empty if no record was found.\n
        """
        # Resolve the DNS query
        try:
            self.answers = DNSQuery.__resolve__(self.domain, rtype=self.type, nameservers=self.nameservers)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            self.answers = []

        # Rotate the nameservers if round robin mode is enabled
        if self.round_robin and len(self.nameservers) > 1:
            self.last_nameserver = self.nameservers[0]
            self.nameservers = self.nameservers[1:] + [self.last_nameserver]

        self.values = self.__parse_values__(self.answers)
        return self.values

    def __get_authoritative_nameservers__(self) -> list:
        """
        Checks the domain's SOA record for the authoritative nameserver of this domain.
        :return: (list) the authoritative nameserver(s).
        """
        # Local variables
        nameserver = []
        domain_sections = self.domain.split(".")

        # Loop through each level of the subdomain to find the SOA for this FQDN.
        while domain_sections:
            # Piece together the remaining domain sections to create our next target domain
            domain = ".".join(domain_sections)

            # Get our SOA record values for this domain and remove the trailing dot from each
            try:
                nameserver = self.__parse_values__(self.__resolve__(domain, rtype="SOA", nameservers=self.nameservers))
                break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                domain_sections.pop(0)
                continue

        # Extract the authoritative nameserver's IP from the response
        nameserver = nameserver[0].split("SOA ")
        nameserver = nameserver[0].split(" ")[0]
        nameserver = nameserver[:-1]
        nameserver = self.__parse_values__(self.__resolve__(nameserver, rtype="A", nameservers=self.nameservers))

        return nameserver

    @staticmethod
    def __resolve__(domain: str, rtype: str = "A", nameservers: list = None) -> list:
        """
        Internal function-like DNS request method.
        :return: (list) returns a list of answer values from the request.
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = nameservers if nameservers else resolver.nameservers

        # Resolve the DNS query
        return DNSQuery.__filter_list__(resolver.resolve(domain, rtype).response.answer[0].to_text().split("\n"))

    @staticmethod
    def __filter_list__(data: list) -> list:
        """
        Filters our list properties to remove blank entries.
        :param data: (list) the list to remove blank entries on.
        :return: (list) the data list stripped of any blank entries.
        """
        return list(filter(None, data))

    @staticmethod
    def __parse_values__(answers: list) -> list:
        """
        Parses the value portion of the query answer into it's own list.
        :param answers: (list) the answers list returned by `__resolve__()` method.
        :return: (list) the value of each answer.
        """
        values = []

        # Loop through each answer and parse it's value section to the values property
        for answer in answers:
            # Save the fourth space separated item as the
            value = answer.split(" ", 4)[-1]
            value = value.replace("\"", "", 1) if value.startswith("\"") else value
            value = value.replace("\"", "", -1) if value.endswith("\"") else value
            values.append(value)

        return DNSQuery.__filter_list__(values)
