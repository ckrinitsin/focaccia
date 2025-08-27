from .arch import Arch
from . import x86, aarch64

supported_architectures: dict[str, Arch] = {
    'x86_64': x86.ArchX86(),
    'aarch64': aarch64.ArchAArch64('little'),
    'aarch64l': aarch64.ArchAArch64('little'),
    'aarch64b': aarch64.ArchAArch64('big'),
}
"""A dictionary containing all supported architectures at their names.

The arch names (keys) should be compatible with the string returned from
`platform.machine()`.
"""
