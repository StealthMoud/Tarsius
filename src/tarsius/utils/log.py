import logging as std_logging
import sys

# --- Custom Log Levels ---
VERBOSE_LEVEL = 15
std_logging.addLevelName(VERBOSE_LEVEL, "VERBOSE")


# Mapping from color names to ANSI codes
COLORS = {
    "BLUE": "\033[38;5;33m",
    "GREEN": "\033[38;5;34m",
    "ORANGE": "\033[38;5;202m",
    "YELLOW": "\033[38;5;226m",
    "RED": "\033[38;5;196m",      # Bright red for critical findings
    "GRAY": "\033[38;5;250m",
    "ERROR_RED": "\033[48;5;196m",
    "CRITICAL_RED": "\033[48;5;196m",
    "ENDC": "\033[0m",
}


class ColoredFormatter(std_logging.Formatter):
    """
    Custom formatter to add colors to logs.
    """

    def __init__(self, fmt=None, datefmt=None, style='%', colorize=False):
        super().__init__(fmt, datefmt, style)
        self.colorize = colorize

    def format(self, record):
        # The message is already formatted by the base class.
        message = super().format(record)
        if not self.colorize:
            return message

        # Priority 1: Use the color specified in the log call `extra`
        color_name = getattr(record, 'color_name', None)
        if color_name and color_name in COLORS:
            return COLORS[color_name] + message + COLORS["ENDC"]

        # Priority 2: Fall back to the color based on the log level
        level_color_map = {
            std_logging.WARNING: COLORS["ORANGE"],
            std_logging.ERROR: COLORS["ERROR_RED"],
            std_logging.CRITICAL: COLORS["CRITICAL_RED"],
        }
        color = level_color_map.get(record.levelno)
        if color:
            return color + message + COLORS["ENDC"]

        return message


# The main logger to be used across the application
logging = std_logging.getLogger("tarsius")


def configure(handlers):
    """
    Configures the root logger based on a list of handlers.
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
    """Logs a critical finding (INFO level, RED color)."""
    if args:
        message = message.format(*args)
    logging.info(message, extra={'color_name': 'RED'}, **kwargs)


def log_bold(message, *args, **kwargs):
    """Logs a critical error message (CRITICAL level)."""
    if args:
        message = message.format(*args)
    logging.critical(message, **kwargs)


def log_orange(message, *args, **kwargs):
    """Logs a medium finding (INFO level, ORANGE color)."""
    if args:
        message = message.format(*args)
    logging.info(message, extra={'color_name': 'ORANGE'}, **kwargs)


def log_yellow(message, *args, **kwargs):
    """Logs a low-finding (INFO level, YELLOW color)."""
    if args:
        message = message.format(*args)
    logging.info(message, extra={'color_name': 'YELLOW'}, **kwargs)


def log_verbose(message, *args, **kwargs):
    """Logs a message with the custom VERBOSE level."""
    if args:
        message = message.format(*args)
    logging.log(VERBOSE_LEVEL, message, extra={'color_name': 'GRAY'}, **kwargs)


def log_severity(severity, message):
    # This function doesn't use formatting, so it remains unchanged
    if severity == 1:
        log_red(message)
    elif severity == 2:
        log_orange(message)
    elif severity == 3:
        log_green(message)
    else:
        log_verbose(message)


# Default configuration
configure(handlers=[{
    "sink": sys.stdout,
    "colorize": False,
    "level": "VERBOSE"
}])
