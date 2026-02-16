from typing import List

from tarsius.definitions.base import FindingBase


class HstsFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Unencrypted Channels"

    @classmethod
    def description(cls) -> str:
        return (
            "Sensitive data must be protected when it is transmitted through the network."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "Testing for Sensitive Information Sent via Unencrypted Channels",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/"
                    "03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels"
                )
            },
            {
                "title": "Testing for Weak Transport Layer Security",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/"
                    "09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "Use HTTPS for the whole web site and redirect any HTTP requests to HTTPS."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CRYP-03"]
