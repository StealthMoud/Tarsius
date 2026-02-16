import os
from importlib.resources import files
from shutil import copytree, rmtree, copy
from urllib.parse import urlparse
import time

from mako.template import Template

from tarsius.reports.jsonreportgenerator import JSONReportGenerator
from tarsius.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL, INFO_LEVEL


def level_to_css_class(level: int) -> str:
    if level == CRITICAL_LEVEL:
        return "severity-critical"
    if level == HIGH_LEVEL:
        return "severity-high"
    if level == MEDIUM_LEVEL:
        return "severity-medium"
    if level == LOW_LEVEL:
        return "severity-low"
    if level == INFO_LEVEL:
        return "severity-info"
    return ""


class HTMLReportGenerator(JSONReportGenerator):
    """
    Generator for HTML format reports.
    """

    def __init__(self):
        super().__init__()
        self._final__path = None

    REPORT_DIR = "report_template"

    def generate_report(self, output_path):
        # make the report folder
        if os.path.isdir(output_path):
            for subdir in ("css", "js"):
                try:
                    rmtree(os.path.join(output_path, subdir))
                except FileNotFoundError:
                    pass

                copytree(
                    str(files("tarsius").joinpath(self.REPORT_DIR, subdir)),
                    os.path.join(output_path, subdir)
                )

        else:
            copytree(str(files("tarsius").joinpath(self.REPORT_DIR)), output_path)

        mytemplate = Template(
            filename=str(files("tarsius").joinpath(self.REPORT_DIR, "report.html")),
            input_encoding="utf-8",
            output_encoding="utf-8"
        )

        report_target_name = urlparse(self._infos['target']).netloc.replace(':', '_')
        report_time = time.strftime('%m%d%Y_%H%M', self._date)

        filename = f"{report_target_name}_{report_time}.html"

        self._final__path = os.path.join(output_path, filename)

        with open(self._final__path, "w", encoding='utf-8') as html_report_file:
            html_report_file.write(
                mytemplate.render_unicode(
                    tarsius_version=self._infos["version"],
                    target=self._infos["target"],
                    scan_date=self._infos["date"],
                    scan_scope=self._infos["scope"],
                    auth_dict=self._infos["auth"],
                    auth_form_dict=self._infos["auth"]["form"] if self._infos.get("auth") is not None else None,
                    crawled_pages_nbr=self._infos["crawled_pages_nbr"],
                    vulnerabilities=self._vulns,
                    anomalies=self._anomalies,
                    additionals=self._additionals,
                    flaws=self._flaw_types,
                    level_to_css_class=level_to_css_class,
                    detailed_report_level=self._infos["detailed_report_level"]
                )
            )

    @property
    def final_path(self):
        return self._final__path
