from typing import List

from tarsius.definitions.base import FindingBase


class SubdomainTakeoverFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Subdomain takeover"

    @classmethod
    def description(cls) -> str:
        return (
            "A DNS CNAME record points to a non existing domain or to a content that an attacker can take control of."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "Microsoft: Prevent dangling DNS entries and avoid subdomain takeover",
                "url": "https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover"
            },
            {
                "title": (
                    "Can I take over XYZ? — a list of services and how to claim (sub)domains with dangling DNS records."
                ),
                "url": "https://github.com/EdOverflow/can-i-take-over-xyz"
            },
            {
                "title": "OWASP: Subdomain Takeover",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/"
                    "02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Prevent dangling DNS entries by making sure you already have control over the pointed domain."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CONF-10"]
