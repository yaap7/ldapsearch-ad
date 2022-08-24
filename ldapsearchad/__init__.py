from .example import add_one
from .ldapsearchad import LdapsearchAd


# version number is just the date of the release.
# with format: YYYY.MM.DD with zero so setuptools is happy
VERSION = "2022.8.24"


def version():
    return VERSION
