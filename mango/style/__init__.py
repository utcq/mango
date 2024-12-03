class STYLE_C:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def __colorize__(text, color, bold=False, underline=False):
    return f"{color}{STYLE_C.BOLD if bold else ''}{STYLE_C.UNDERLINE if underline else ''}{text}{STYLE_C.END}"

def LOG(msg: str):
    print(
        __colorize__("[LOG]", STYLE_C.CYAN),
        __colorize__(msg, STYLE_C.WHITE)
    )

def WARN(msg: str):
    print(
        __colorize__("[WARN]", STYLE_C.YELLOW),
        __colorize__(msg, STYLE_C.WHITE)
    )

def ERROR(msg: str):
    print(
        __colorize__("[ERROR]", STYLE_C.RED),
        __colorize__(msg, STYLE_C.WHITE)
    )

def OK(msg: str):
    print(
        __colorize__("[OK]", STYLE_C.GREEN),
        __colorize__(msg, STYLE_C.WHITE)
    )
