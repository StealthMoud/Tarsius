from typing import List

from tarsius.definitions.base import FindingBase


class HtaccessBypassFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Htaccess Bypass"

    @classmethod
    def description(cls) -> str:
        return (
            "Htaccess files are used to restrict access to some files or HTTP method. "
            "In some case it may be possible to bypass this restriction and access the files."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "A common Apache .htaccess misconfiguration",
                "url": "http://blog.teusink.net/2009/07/common-apache-htaccess-misconfiguration.html"
            },
            {
                "title": "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory",
                "url": "https://cwe.mitre.org/data/definitions/538.html"
            },
            {
                "title": "OWASP: HTTP Methods",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/"
                    "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Make sure every HTTP method is forbidden if the credentials are bad."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CONF-06"]
