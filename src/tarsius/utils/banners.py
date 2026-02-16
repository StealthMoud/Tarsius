from tarsius import TARSIUS_VERSION
from tarsius.utils.log import log_yellow


def print_banner():
    cyan = "\033[38;5;51m"
    reset = "\033[0m"
    banner = f"""{cyan}
 ████████╗ █████╗ ██████╗ ███████╗██╗██╗   ██╗███████╗
 ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║██║   ██║██╔════╝
    ██║   ███████║██████╔╝███████╗██║██║   ██║███████╗
    ██║   ██╔══██║██╔══██╗╚════██║██║██║   ██║╚════██║
    ██║   ██║  ██║██║  ██║███████║██║╚██████╔╝███████║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚══════╝{reset}"""
    print(banner)
    log_yellow(f"Tarsius {TARSIUS_VERSION} - Black Box Web Scanner")


def print_easter_eggs():
    pass
