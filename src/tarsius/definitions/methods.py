from typing import List

from tarsius.definitions.base import FindingBase


class MethodsFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "HTTP Methods"

    @classmethod
    def description(cls) -> str:
        return (
            "While GET and POST are by far the most common methods that are used to access "
            "information provided by a web server, HTTP allows several other (and somewhat less known) methods. "
            "Some of these can be used for nefarious purposes if the web server is misconfigured."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: HTTP Methods",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/"
                    "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "This is only for informational purposes."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "additional"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CONF-06"]
