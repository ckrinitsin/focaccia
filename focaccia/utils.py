import ctypes
import sys
import shutil

from .compare import ErrorSeverity

def float_bits_to_uint(v: float) -> int:
    """Bit-cast a float to a 32-bit integer."""
    return ctypes.c_uint32.from_buffer(ctypes.c_float(v)).value

def uint_bits_to_float(v: int) -> float:
    """Bit-cast a 32-bit integer to a float."""
    return ctypes.c_float.from_buffer(ctypes.c_uint32(v)).value

def double_bits_to_uint(v: float) -> int:
    """Bit-cast a double to a 64-bit integer."""
    return ctypes.c_uint64.from_buffer(ctypes.c_double(v)).value

def uint_bits_to_double(v: int) -> float:
    """Bit-cast a 64-bit integer to a double."""
    return ctypes.c_double.from_buffer(ctypes.c_uint64(v)).value

def print_separator(separator: str = '-', stream=sys.stdout, count: int = 80):
    maxtermsize = count
    termsize = shutil.get_terminal_size((80, 20)).columns
    print(separator * min(termsize, maxtermsize), file=stream)

def print_result(result, min_severity: ErrorSeverity):
    """Print a comparison result."""
    shown = 0
    suppressed = 0

    for res in result:
        # Filter errors by severity
        errs = [e for e in res['errors'] if e.severity >= min_severity]
        suppressed += len(res['errors']) - len(errs)
        shown += len(errs)

        if errs:
            pc = res['pc']
            print_separator()
            print(f'For PC={hex(pc)}')
            print_separator()

        # Print all non-suppressed errors
        for n, err in enumerate(errs, start=1):
            print(f' {n:2}. {err}')

        if errs:
            print()
            print(f'Expected transformation: {res["ref"]}')
            print(f'Actual difference:       {res["txl"]}')

    print()
    print('#' * 60)
    print(f'Found {shown} errors.')
    print(f'Suppressed {suppressed} low-priority errors'
          f' (showing {min_severity} and higher).')
    print('#' * 60)
    print()
