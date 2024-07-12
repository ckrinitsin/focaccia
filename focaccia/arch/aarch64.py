"""Description of 64-bit ARM."""
from typing import Literal

from .arch import Arch

archname = 'aarch64'

regnames = [
    'PC', 'SP', 'LR',
    'CPSR',

    'X0', 'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7', 'X8', 'X9',
    'X10', 'X11', 'X12', 'X13', 'X14', 'X15', 'X16', 'X17', 'X18', 'X19',
    'X20', 'X21', 'X22', 'X23', 'X24', 'X25', 'X26', 'X27', 'X28', 'X29',
    'X30',

    'Q0', 'Q1', 'Q2', 'Q3', 'Q4', 'Q5', 'Q6', 'Q7', 'Q8', 'Q9',
    'Q10', 'Q11', 'Q12', 'Q13', 'Q14', 'Q15',

    'V0', 'V1', 'V2', 'V3', 'V4', 'V5', 'V6', 'V7', 'V8', 'V9',
    'V10', 'V11', 'V12', 'V13', 'V14', 'V15', 'V16', 'V17', 'V18', 'V19',
    'V20', 'V21', 'V22', 'V23', 'V24', 'V25', 'V26', 'V27', 'V28', 'V29',
    'V30', 'V31',

    'N', 'Z', 'C', 'V', 'Q',
    'SSBS', 'PAN', 'DIT', 'GE',
    'E', 'A', 'I', 'F', 'M',
]

def decompose_cpsr(cpsr: int) -> dict[str, int]:
    """Extract individual flag values from the CPSR register."""
    return {
        'N':    (cpsr & (1 << 31)) != 0,
        'Z':    (cpsr & (1 << 30)) != 0,
        'C':    (cpsr & (1 << 29)) != 0,
        'V':    (cpsr & (1 << 28)) != 0,
        'Q':    (cpsr & (1 << 27)) != 0,
        # Reserved: [26:24]
        'SSBS': (cpsr & (1 << 23)) != 0,
        'PAN':  (cpsr & (1 << 22)) != 0,
        'DIT':  (cpsr & (1 << 21)) != 0,
        # Reserved: [20]
        'GE':   (cpsr & (0b1111 << 16)) != 0,
        # Reserved: [15:10]
        'E':    (cpsr & (1 << 9)) != 0,
        'A':    (cpsr & (1 << 8)) != 0,
        'I':    (cpsr & (1 << 7)) != 0,
        'F':    (cpsr & (1 << 6)) != 0,
        # Reserved: [5:4]
        'M':    (cpsr & 0b1111) != 0,
    }

class ArchAArch64(Arch):
    def __init__(self, endianness: Arch.Endianness):
        super().__init__(archname, regnames, 64, endianness)
