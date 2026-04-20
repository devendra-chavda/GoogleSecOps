"""Handle the logger."""

import logging
import sys

from . import consts

LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}

try:
    applogger = logging.getLogger("azure")
    applogger.setLevel(LOG_LEVELS.get(consts.LOG_LEVEL.upper(), logging.INFO))
except Exception:
    applogger = logging.getLogger("azure")
    applogger.setLevel(logging.INFO)
finally:
    handler = logging.StreamHandler(stream=sys.stdout)
    applogger.addHandler(handler)
