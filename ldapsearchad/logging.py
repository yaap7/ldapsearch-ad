from logging import info
from logging import error
from logging import getLogger
from logging import StreamHandler
from logging import Formatter
from logging import INFO as LOGGING_INFO

from .colors import c_red
from .colors import c_orange
from .colors import c_blue
from .colors import c_green

from sys import stdout


def log_title(title, level=2):
    heading = "#" * level
    info(f"\x1b[1;37;40m{heading} {title} {heading}\x1b[0m")


def log_error(message):
    error(f'{c_red("[-]")} {message}')


def log_warning(message):
    info(f'{c_orange("[!]")} {message}')


def log_info(message):
    info(f'{c_blue("[+]")} {message}')


def log_success(message):
    info(f'{c_green("[*]")} {message}')


# Configure default logging to stdout
logger = getLogger()
handler = StreamHandler(stdout)
logger.setLevel(LOGGING_INFO)
formatter = Formatter(fmt="%(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
