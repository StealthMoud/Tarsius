from .reportgenerator import ReportGenerator
from .csvreportgenerator import CSVReportGenerator
from .htmlreportgenerator import HTMLReportGenerator
from .jsonreportgenerator import JSONReportGenerator
from .markdownreportgenerator import MarkdownReportGenerator
from .txtreportgenerator import TXTReportGenerator
from .xmlreportgenerator import XMLReportGenerator

GENERATORS = {
    "csv": CSVReportGenerator,
    "html": HTMLReportGenerator,
    "json": JSONReportGenerator,
    "md": MarkdownReportGenerator,
    "txt": TXTReportGenerator,
    "xml": XMLReportGenerator
}


def get_report_generator_instance(report_format: str = "html"):
    return GENERATORS[report_format]()
