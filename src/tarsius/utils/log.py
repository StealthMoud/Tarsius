import logging as std_logging
import sys


VERBOSE_LEVEL = 15
std_logging.addLevelName(VERBOSE_LEVEL, "VERBOSE")


# maping color names to ansi codes sory for the mess
COLORS = {
    "BLUE": "\033[38;5;33m",
    "GREEN": "\033[38;5;34m",
    "ORANGE": "\033[38;5;202m",
    "YELLOW": "\033[38;5;226m",
    "RED": "\033[38;5;196m",      # briyht red for critical thngs
    "CYAN": "\033[38;5;51m",
    "GRAY": "\033[38;5;250m",
    "ERROR_RED": "\033[48;5;196m",
    "CRITICAL_RED": "\033[48;5;196m",
    "ENDC": "\033[0m",
}


class ColoredFormatter(std_logging.Formatter):
    """
    custom formater added for colors in the logs.
    """

    def __init__(self, fmt=None, datefmt=None, style='%', colorize=False):
        super().__init__(fmt, datefmt, style)
        self.colorize = colorize

    def format(self, record):
        # we format the mesage here with colors from the base class
        message = super().format(record)
        if not self.colorize:
            return message

        # adding visual prefixes for levels
        prefixes = {
            std_logging.INFO: "[*] ",
            VERBOSE_LEVEL: "[V] ",
            std_logging.WARNING: "[!] ",
            std_logging.ERROR: "[!] ",
            std_logging.CRITICAL: "[!!] ",
        }
        prefix = prefixes.get(record.levelno, "")
        if prefix and not message.startswith("["):
            message = prefix + message

        # check if we have custom color from the log call
        color_name = getattr(record, 'color_name', None)
        if color_name and color_name in COLORS:
            return COLORS[color_name] + message + COLORS["ENDC"]

        # use standard color based on the level
        level_color_map = {
            VERBOSE_LEVEL: COLORS["GRAY"],
            std_logging.INFO: COLORS["BLUE"],
            std_logging.WARNING: COLORS["ORANGE"],
            std_logging.ERROR: COLORS["RED"],
            std_logging.CRITICAL: COLORS["CRITICAL_RED"],
        }
        color = level_color_map.get(record.levelno)
        if color:
            return color + message + COLORS["ENDC"]

        return message


# main loger for the whole app
logging = std_logging.getLogger("tarsius")


def configure(handlers):
    """
    setup the root loger with handlers.
    """
    logging.handlers = []
    logging.setLevel(std_logging.DEBUG)

    level_map = {
        "DEBUG": std_logging.DEBUG,
        "INFO": std_logging.INFO,
        "VERBOSE": VERBOSE_LEVEL,
        "WARNING": std_logging.WARNING,
        "ERROR": std_logging.ERROR,
        "CRITICAL": std_logging.CRITICAL,
    }

    for handler_conf in handlers:
        sink = handler_conf.get("sink")
        level_str = handler_conf.get("level", "INFO")
        level = level_map.get(level_str, std_logging.INFO)

        handler = None
        if sink in (sys.stdout, sys.stderr):
            handler = std_logging.StreamHandler(sink)
        elif isinstance(sink, str):
            handler = std_logging.FileHandler(sink)

        if handler:
            colorize = handler_conf.get("colorize", False) and sink in (sys.stdout, sys.stderr)
            formatter = ColoredFormatter("{message}", style='{', colorize=colorize)
            handler.setFormatter(formatter)
            handler.setLevel(level)
            logging.addHandler(handler)


def log_blue(message, *args, **kwargs):
    if args:
        message = message.format(*args)
    logging.info(message, extra={'color_name': 'BLUE'}, **kwargs)


def log_green(message, *args, **kwargs):
    if args:
        message = message.format(*args)
    logging.info(message, extra={'color_name': 'GREEN'}, **kwargs)


def log_red(message, *args, **kwargs):
    """log crazy important findings in red."""
    if args:
        message = message.format(*args)
    logging.info(message, extra={'color_name': 'RED'}, **kwargs)


def log_bold(message, *args, **kwargs):
    """log very bad server errors here."""
    if args:
        message = message.format(*args)
    logging.critical(message, **kwargs)


def log_orange(message, *args, **kwargs):
    """log medium findings in orynge."""
    if args:
        message = message.format(*args)
    logging.info(message, extra={'color_name': 'ORANGE'}, **kwargs)


def log_yellow(message, *args, **kwargs):
    """log smal finding in yelow."""
    if args:
        message = message.format(*args)
    logging.info(message, extra={'color_name': 'YELLOW'}, **kwargs)


def log_verbose(message, *args, **kwargs):
    """log verbose stuff."""
    if args:
        message = message.format(*args)
    logging.log(VERBOSE_LEVEL, message, extra={'color_name': 'GRAY'}, **kwargs)


def log_severity(severity, message):
    # helper to log based on severity number
    if severity == 1:
        log_red(message)
    elif severity == 2:
        log_orange(message)
    elif severity == 3:
        log_green(message)
    else:
        log_verbose(message)


# default setup
configure(handlers=[{
    "sink": sys.stdout,
    "colorize": sys.stdout.isatty(),
    "level": "VERBOSE"
}])
