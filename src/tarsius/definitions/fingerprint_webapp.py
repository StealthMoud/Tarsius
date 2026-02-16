from typing import List

from tarsius.definitions.base import FindingBase


class SoftwareVersionDisclosureFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Fingerprint web application framework"

    @classmethod
    def description(cls) -> str:
        return (
            "The version of a web application framework can be identified "
            "due to the presence of its specific fingerprints."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Fingerprint Web Application Framework",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/"
                    "01-Information_Gathering/08-Fingerprint_Web_Application_Framework.html"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "This is only for informational purposes."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INFO-08"]
