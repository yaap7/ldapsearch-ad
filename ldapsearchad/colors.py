def c_green(message):
    """Color text for good configuration."""
    return f"\x1b[0;32;40m{message}\x1b[0m"


def c_orange(message):
    """Color text for weak configuration."""
    return f"\x1b[0;33;40m{message}\x1b[0m"


def c_red(message):
    """Color text for bad configuration."""
    return f"\x1b[0;31;40m{message}\x1b[0m"


def c_white_on_red(message):
    """Color text for very bad configuration."""
    return f"\x1b[1;37;41m{message}\x1b[0m"


def c_blue(message):
    """Color text for information."""
    return f"\x1b[0;34;40m{message}\x1b[0m"


def c_cyan(message):
    """Color text for general usefull information."""
    return f"\x1b[0;36;40m{message}\x1b[0m"


def c_purple(message):
    """Color text for abnormal behavior of the tool itself."""
    return f"\x1b[0;35;40m{message}\x1b[0m"
