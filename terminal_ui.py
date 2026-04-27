import sys
import time


class Colors:
    BLACK = "\033[30m"; RED = "\033[31m"; GREEN = "\033[32m"
    YELLOW = "\033[33m"; BLUE = "\033[34m"; MAGENTA = "\033[35m"
    CYAN = "\033[36m"; WHITE = "\033[37m"
    BRIGHT_RED = "\033[91m"; BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"; BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"; BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    BOLD = "\033[1m"; DIM = "\033[2m"; UNDERLINE = "\033[4m"
    RESET = "\033[0m"
    BG_RED = "\033[41m"; BG_GREEN = "\033[42m"; BG_CYAN = "\033[46m"


def _disable_colors():
    for attr in dir(C):
        if not attr.startswith("_"):
            setattr(C, attr, "")


def _configure_stdout_encoding():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _enable_windows_ansi():
    if sys.platform != "win32":
        return

    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )
    except Exception:
        _disable_colors()


C = Colors()
_configure_stdout_encoding()
_enable_windows_ansi()

try:
    BANNER = f"""
{C.BRIGHT_RED}    _   _       _ _   _         _ _          _             {C.RESET}
{C.BRIGHT_YELLOW}   | \\ | |_   _(_) |_| | ____ _| (_)______ _| |_ ___  _ __ {C.RESET}
{C.BRIGHT_GREEN}   |  \\| | | | | | __| |/ / _` | | |_  / _` | __/ _ \\| '__|{C.RESET}
{C.BRIGHT_CYAN}   | |\\  | |_| | | |_|   < (_| | | |/ / (_| | || (_) | |   {C.RESET}
{C.BRIGHT_BLUE}   |_| \\_|\\__,_|_|\\__|_|\\_\\__,_|_|_/___\\__,_|\\__\\___/|_|   {C.RESET}

{C.BOLD}{C.BRIGHT_WHITE}   <<<  Nuitka Static Unpacker v7.3 | by dimareverse  >>>{C.RESET}
{C.BOLD}{C.BRIGHT_WHITE}   <<<  Authorized static analysis | Dynamic lab mode (opt) >>>{C.RESET}
"""
except Exception:
    BANNER = """
   Nuitka Static Unpacker v7.3 - by dimareverse
   Authorized static analysis | Dynamic lab mode (optional)
"""


class ProgressBar:
    def __init__(self, total, desc="Processing", width=40, spinner="fire"):
        self.total = max(total, 1)
        self.current = 0
        self.desc = desc
        self.width = width
        self.start_time = time.time()
        self.spinner_frames = ["*", "+", "x", "+"]
        self.frame = 0

    def update(self, n=1):
        self.current = min(self.current + n, self.total)
        self.frame = (self.frame + 1) % len(self.spinner_frames)
        self._render()

    def _render(self):
        progress = self.current / self.total
        filled = int(self.width * progress)
        bar = ""
        for i in range(self.width):
            if i < filled:
                if i < self.width * 0.3:
                    bar += f"{C.BRIGHT_RED}#"
                elif i < self.width * 0.6:
                    bar += f"{C.BRIGHT_YELLOW}#"
                else:
                    bar += f"{C.BRIGHT_GREEN}#"
            else:
                bar += f"{C.DIM}."
        bar += C.RESET
        elapsed = time.time() - self.start_time
        eta = (elapsed / self.current * (self.total - self.current)) if self.current > 0 else 0
        s = self.spinner_frames[self.frame]
        status = (
            f"\r{C.BOLD}{C.BRIGHT_CYAN}[{s}]{C.RESET} "
            f"{C.BRIGHT_WHITE}{self.desc}{C.RESET} [{bar}] "
            f"{C.BRIGHT_YELLOW}{progress * 100:5.1f}%{C.RESET} "
            f"{C.DIM}({self.current}/{self.total}){C.RESET} "
            f"{C.BRIGHT_MAGENTA}ETA: {int(eta)}s{C.RESET}"
        )
        print(status, end="", flush=True)

    def finish(self, message="Done!"):
        print(f"\r{' ' * 120}\r", end="")
        print(
            f"{C.BRIGHT_GREEN}[OK]{C.RESET} {C.BRIGHT_WHITE}{self.desc}{C.RESET}: "
            f"{C.BRIGHT_GREEN}{message}{C.RESET}"
        )


def print_section(title):
    width = 65
    print()
    print(f"{C.BRIGHT_CYAN}{'=' * width}{C.RESET}")
    centered = title.center(width - 4)
    print(
        f"{C.BRIGHT_CYAN}||{C.RESET} {C.BOLD}{C.BRIGHT_WHITE}{centered}{C.RESET} "
        f"{C.BRIGHT_CYAN}||{C.RESET}"
    )
    print(f"{C.BRIGHT_CYAN}{'=' * width}{C.RESET}")


def log(msg):
    print(f"{C.BRIGHT_CYAN}[**]{C.RESET} {msg}")


def log_ok(msg):
    print(f"{C.BRIGHT_GREEN}[OK]{C.RESET} {msg}")


def log_err(msg):
    print(f"{C.BRIGHT_RED}[!!]{C.RESET} {msg}")


def log_warn(msg):
    print(f"{C.BRIGHT_YELLOW}[!!]{C.RESET} {msg}")


def log_fire(msg):
    print(f"{C.BRIGHT_RED}[>>]{C.RESET} {C.BOLD}{msg}{C.RESET}")
