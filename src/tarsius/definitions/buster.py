from typing import List

from tarsius.definitions.base import FindingBase


class BusterFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Review Webserver Metafiles for Information Leakage"

    @classmethod
    def description(cls) -> str:
        return (
            "Test various metadata files for information leakage of the web application’s path(s), or functionality"
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Review Webserver Metafiles for Information Leakage",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/"
                    "01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"
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
        return ["WSTG-INFO-03"]
