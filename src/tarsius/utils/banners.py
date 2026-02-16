from tarsius import TARSIUS_VERSION
from tarsius.utils.log import log_yellow


def print_banner():
    banner = """
 ████████╗ █████╗ ██████╗ ███████╗██╗██╗   ██╗███████╗
 ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║██║   ██║██╔════╝
    ██║   ███████║██████╔╝███████╗██║██║   ██║███████╗
    ██║   ██╔══██║██╔══██╗╚════██║██║██║   ██║╚════██║
    ██║   ██║  ██║██║  ██║███████║██║╚██████╔╝███████║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚══════╝"""
    print(banner)
    log_yellow(f"Tarsius {TARSIUS_VERSION} - Black Box Web Scanner")


def print_easter_eggs():
    """Deprecated: Kept for backward compatibility."""
    pass
