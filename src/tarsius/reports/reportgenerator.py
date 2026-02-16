import time

from httpx import Response

from tarsius.network.response import detail_response


class ReportGenerator:
    def __init__(self):
        self._infos = {}
        self._date = None
        self._flaw_types = {}
        self._vulns = {}
        self._anomalies = {}
        self._additionals = {}

    # pylint: disable=too-many-positional-arguments
    def set_report_info(
        self,
        target: str,
        scope,
        date,
        version,
        auth,
        crawled_pages: list,
        crawled_pages_nbr: int,
        detailed_report_level: int
    ):
        """set info for the scan"""
        self._infos["target"] = target
        self._infos["date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", date)
        self._infos["version"] = version
        self._infos["scope"] = scope
        self._infos["auth"] = auth
        self._infos["crawled_pages_nbr"] = crawled_pages_nbr
        if detailed_report_level in (1, 2):
            self._infos["crawled_pages"] = crawled_pages
        self._infos["detailed_report_level"] = detailed_report_level
        self._date = date

    @property
    def scan_date(self):
        return self._date

    def generate_report(self, output_path):
        raise NotImplementedError("Must be overridden")

    # vulnz
    def add_vulnerability_type(self, name: str, description: str = "", solution: str = "", references=None, wstg=None):
        """
        adds a vuln type to the report. we add them as we find them.
        """
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references,
                "wstg": wstg
            }
        if name not in self._vulns:
            self._vulns[name] = []

    # pylint: disable=too-many-positional-arguments
    def add_vulnerability(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg: str = None,
        response: Response = None
    ):
        """
        save vuln info to print later.
        """
        vuln_dict = {
            "level": level,
            "request": request,
            "parameter": parameter,
            "info": info,
            "module": module,
            "wstg": wstg
        }
        if self._infos.get("detailed_report_level"):
            vuln_dict["detail"] = {
                "response": detail_response(response)
            }
        if category not in self._vulns:
            self._vulns[category] = []
        self._vulns[category].append(vuln_dict)

    # anomalyz
    def add_anomaly_type(self, name, description="", solution="", references=None, wstg=None):
        """
        adds an anomaly type to the report.
        """
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references,
                "wstg": wstg
            }
        if name not in self._anomalies:
            self._anomalies[name] = []

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
        """
        save anomaly info for report.
        """
        anom_dict = {
            "request": request,
            "info": info,
            "level": level,
            "parameter": parameter,
            "module": module,
            "wstg": wstg
        }
        if self._infos.get("detailed_report_level"):
            anom_dict["detail"] = {
                "response": detail_response(response)
            }
        if category not in self._anomalies:
            self._anomalies[category] = []
        self._anomalies[category].append(anom_dict)

    # mor stuff
    def add_additional_type(self, name, description="", solution="", references=None, wstg=None):
        """
        adds more types to the report.
        """
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references,
                "wstg": wstg
            }
        if name not in self._additionals:
            self._additionals[name] = []

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
        """
        save extra info for report.
        """
        addition_dict = {
            "request": request,
            "info": info,
            "level": level,
            "parameter": parameter,
            "module": module,
            "wstg": wstg
        }
        if self._infos.get("detailed_report_level"):
            addition_dict["detail"] = {
                "response": detail_response(response)
            }
        if category not in self._additionals:
            self._additionals[category] = []
        self._additionals[category].append(addition_dict)
