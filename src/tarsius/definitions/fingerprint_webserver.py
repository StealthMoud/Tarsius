from typing import List

from tarsius.definitions.base import FindingBase


class WebServerVersionDisclosureFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Fingerprint web server"

    @classmethod
    def description(cls) -> str:
        return "The version of a web server can be identified due to the presence of its specific fingerprints."

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Fingerprint Web Server",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server.html"
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
        return ["WSTG-INFO-02"]
