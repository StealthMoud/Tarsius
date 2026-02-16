import codecs

from tarsius.network.web import http_repr, curl_repr
from tarsius.reports.reportgenerator import ReportGenerator

NB_COLUMNS = 80

# TODO: should use more the python format mini-language
# http://docs.python.org/2/library/string.html#format-specification-mini-language


def center(row: str) -> str:
    if len(row) >= NB_COLUMNS:
        return row
    return row.rjust(len(row) + int((NB_COLUMNS - len(row)) / 2.0))


def title(row: str) -> str:
    return f"{row}\n{'-' * len(row.strip())}\n"


separator = ("*" * NB_COLUMNS) + "\n"


class TXTReportGenerator(ReportGenerator):
    """
    This class generates a Tarsius report in TXT format.
    """

    def generate_report(self, output_path):
        """
        Create a TXT file encoded as UTF-8 with a report of the vulnerabilities which have been logged with
        the methods add_vulnerability and add_anomaly.
        """
        with codecs.open(output_path, mode="w", encoding="UTF-8") as txt_report_file:
            try:
                txt_report_file.write(separator)
                txt_report_file.write(center(f"{self._infos['version']} - tarsius-scanner.github.io\n"))
                txt_report_file.write(center(f"Report for {self._infos['target']}\n"))
                txt_report_file.write(center(f"Date of the scan : {self._infos['date']}\n"))
                txt_report_file.write(center(f"Crawled pages : {self._infos['crawled_pages_nbr']}\n"))
                if "scope" in self._infos:
                    txt_report_file.write(center(f"Scope of the scan : {self._infos['scope']}\n"))
                txt_report_file.write(separator)
                txt_report_file.write("\n")

                self._write_auth_info(txt_report_file)

                txt_report_file.write(title("Summary of vulnerabilities :"))
                for category, vulnerabilities in self._vulns.items():
                    txt_report_file.write(f"{category} : {len(vulnerabilities):>3}\n".rjust(NB_COLUMNS))
                txt_report_file.write(separator)

                for category, vulnerabilities in self._vulns.items():
                    if vulnerabilities:
                        txt_report_file.write("\n")
                        txt_report_file.write(title(category))
                        for vuln in vulnerabilities:
                            txt_report_file.write(vuln["info"])
                            txt_report_file.write("\n")
                            txt_report_file.write(f"WSTG code: {vuln['wstg']}")
                            txt_report_file.write("\n")
                            # f.write("Involved parameter : {0}\n".format(vuln["parameter"]))
                            txt_report_file.write("Evil request:\n")
                            txt_report_file.write(http_repr(vuln["request"]))
                            txt_report_file.write("\n")
                            txt_report_file.write(f"cURL command PoC : \"{curl_repr(vuln['request'])}\"")
                            txt_report_file.write("\n\n")
                            txt_report_file.write(center("*   *   *\n\n"))
                        txt_report_file.write(separator)

                txt_report_file.write("\n")

                txt_report_file.write(title("Summary of anomalies :"))
                for category, vulnerabilities in self._anomalies.items():
                    txt_report_file.write(f"{category} : {len(vulnerabilities):>3}\n".rjust(NB_COLUMNS))
                txt_report_file.write(separator)

                for category, anomalies in self._anomalies.items():
                    if anomalies:
                        txt_report_file.write("\n")
                        txt_report_file.write(title(category))
                        for anom in anomalies:
                            txt_report_file.write(anom["info"])
                            txt_report_file.write("\n")
                            txt_report_file.write(f"WSTG code: {anom['wstg']}")
                            txt_report_file.write("\n")
                            txt_report_file.write("Evil request:\n")
                            txt_report_file.write(http_repr(anom["request"]))
                            txt_report_file.write("\n\n")
                            txt_report_file.write(center("*   *   *\n\n"))
                        txt_report_file.write(separator)

                txt_report_file.write(title("Summary of additionals :"))
                for category, additionnals in self._additionals.items():
                    txt_report_file.write(f"{category} : {len(additionnals):>3}\n".rjust(NB_COLUMNS))
                txt_report_file.write(separator)

                for category, additionnals in self._additionals.items():
                    if additionnals:
                        txt_report_file.write("\n")
                        txt_report_file.write(title(category))
                        for additional in additionnals:
                            txt_report_file.write(additional["info"])
                            txt_report_file.write("\n")
                            txt_report_file.write(f"WSTG: {additional['wstg']}")
                            txt_report_file.write("\n\n")
                            txt_report_file.write(center("*   *   *\n\n"))
                        txt_report_file.write(separator)

            finally:
                txt_report_file.close()

    def _write_auth_info(self, txt_report_file: codecs.StreamReaderWriter):
        """
        Write the authentication section explaining what method, fields, url were used and also if it has been
        successful
        """
        if self._infos.get("auth") is None:
            return
        auth_dict = self._infos["auth"]
        txt_report_file.write(title("Authentication :"))
        txt_report_file.write(f"Url: {auth_dict['url']}\n")
        txt_report_file.write(f"Logged in: {auth_dict['logged_in']}\n")

        auth_form_dict = auth_dict.get("form")
        if auth_form_dict is None or len(auth_form_dict) == 0:
            return
        txt_report_file.write(f"Login field: {auth_form_dict['login_field']}\n")
        txt_report_file.write(f"Password field: {auth_form_dict['password_field']}\n")
        txt_report_file.write("\n")
        txt_report_file.write(separator)
