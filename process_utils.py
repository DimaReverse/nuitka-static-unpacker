import subprocess
import sys


def _suppress_windows_error_dialogs():
    if sys.platform != "win32":
        return

    try:
        import ctypes as _ctypes_err
        sem_failcriticalerrors = 0x0001
        sem_nogpfault_errorbox = 0x0002
        sem_noalignmentfault_except = 0x0004
        sem_noopenfile_errorbox = 0x8000
        _ctypes_err.windll.kernel32.SetErrorMode(
            sem_failcriticalerrors
            | sem_nogpfault_errorbox
            | sem_noopenfile_errorbox
            | sem_noalignmentfault_except
        )
        try:
            _ctypes_err.windll.kernel32.SetThreadErrorMode(
                sem_failcriticalerrors
                | sem_nogpfault_errorbox
                | sem_noopenfile_errorbox,
                None,
            )
        except Exception:
            pass
    except Exception:
        pass


_suppress_windows_error_dialogs()
SAFE_SUBPROCESS_FLAGS = 0x08000000 if sys.platform == "win32" else 0


def run_external_tool(cmd, *, timeout=60, input_bytes=None):
    """Run an external CLI tool and convert hard failures into return objects."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            input=input_bytes,
            creationflags=SAFE_SUBPROCESS_FLAGS,
        )
    except subprocess.TimeoutExpired:
        class _R:
            returncode = -1
            stdout = b""
            stderr = b"TIMEOUT"
        return _R()
    except (OSError, subprocess.SubprocessError) as e:
        class _R:
            returncode = -1
            stdout = b""
            stderr = str(e).encode()
        return _R()
