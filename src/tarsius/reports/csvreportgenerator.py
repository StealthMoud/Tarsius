import csv

from httpx import Response

from tarsius.reports.reportgenerator import ReportGenerator


class CSVReportGenerator(ReportGenerator):
    """This class allows generating reports in CSV format.
    """

    def __init__(self):
        super().__init__()
        self._vulns = []
        self._anomalies = []
        self._additionals = []

    def generate_report(self, output_path):
        """
        Generate a CSV report of the vulnerabilities, anomalies and additionals which have
        been previously logged with the log* methods.
        """
        with open(output_path, 'w', newline='', encoding="utf-8") as csv_fd:
            writer = csv.writer(csv_fd, quoting=csv.QUOTE_NONNUMERIC, doublequote=False, escapechar="\\")
            writer.writerow([
                "category",
                "level",
                "description",
                "method",
                "parameter",
                "url",
                "body",
                "referer",
                "wstg",
                "auth",
                "module"
            ])
            writer.writerows(self._vulns)
            writer.writerows(self._anomalies)
            writer.writerows(self._additionals)

    # pylint: disable=too-many-positional-arguments
    def add_vulnerability(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg=None,
        response: Response = None
    ):
        """
        Store the information about a vulnerability.
        """
        if request is not None:
            self._vulns.append(
                [
                    category, level, info, request.method, parameter,
                    request.url, request.encoded_data, request.referer,
                    wstg, self._infos["auth"], module
                ]
            )

    # pylint: disable=too-many-positional-arguments
    def add_anomaly(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg=None,
        response: Response = None
    ):
        """Store the information about an anomaly met during the attack."""
        if request is not None:
            self._anomalies.append(
                [
                    category, level, info, request.method, parameter,
                    request.url, request.encoded_data, request.referer,
                    wstg, self._infos["auth"], module
                ]
            )

    # pylint: disable=too-many-positional-arguments
    def add_additional(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg=None,
        response: Response = None
    ):
        """Store the information about an additional."""
        if request is not None:
            self._additionals.append(
                [
                    category, level, info, request.method, parameter,
                    request.url, request.encoded_data, request.referer,
                    wstg, self._infos["auth"], module
                ]
            )

    # We don't want description of each vulnerability for this report format
    def add_vulnerability_type(self, name, description="", solution="", references=None, wstg=None):
        pass

    def add_anomaly_type(self, name, description="", solution="", references=None, wstg=None):
        pass

    def add_additional_type(self, name, description="", solution="", references=None, wstg=None):
        pass
