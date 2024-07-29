from typing import dataclass_transform
import bitstring
from pyvex.lifting.util import *
from pyvex.lifting import register
import yan85_config as yconf
import logging

# in order for angr to perform any sort of analysis on binary code
# we first need to translate, or lift, this code into an
# intermediate representation (IR) that angr uses, called VEX

# setup logging.
logging.basicConfig(level=logging.INFO)
l = logging.getLogger(__name__)

"""
Yan85 Instructions are 3 bytes long, and have 2 registers (r1) and (r2),
defined here as x, y and z.

Parent class of every Yan85 Instructions.
"""
class Yan85Instruction(Instruction):
    """
    This parse functions takes our bytecode and transforms it into a bitstream,
    which is just a stream of bits, we also log our 2 registers.
    """
    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        l.info(data)
        return data

    """
    static method, which means we can call it outside of the class.
    this computers our bin_format for each of our instructions, it is
    a somewhat generic function.
    """
    @staticmethod
    def parse_bin_format(op):
        if "y" in yconf.ARG1:
            # yconf.ARG1 = f"{op:08b}"
            l.info(f"{op:08b}" + yconf.ARG2 + yconf.ARG3)
            return f"{op:08b}" + yconf.ARG2 + yconf.ARG3
        if "y" in yconf.ARG2:
            # yconf.ARG2 = f"{op:08b}"
            l.info(yconf.ARG1 + f"{op:08b}" + yconf.ARG3)
            return yconf.ARG1 + f"{op:08b}" + yconf.ARG3
        if "y" in yconf.ARG3:
            # yconf.ARG3 = f"{op:08b}"
            l.info(yconf.ARG1 + yconf.ARG2 + f"{op:08b}")
            return yconf.ARG1 + yconf.ARG2 + f"{op:08b}"

"""
Computes a IMM instruction.
"""
class Instruction_IMM(Yan85Instruction):
    """
    helper function to call our parse_bin_format function in Yan85Instruction,
    which is somewhat generic to every instructions.
    """
    @staticmethod
    def compute_bin_format():
        return Yan85Instruction.parse_bin_format(yconf.IMM)

    bin_format = compute_bin_format()
    name = "IMM"

    """
    this method computes the actual IMM instruction.
    """
    def compute_result(self, *args):
        l.info("compute result called (IMM)")
        l.info(self.data)
        # self.put(self.constant(self.imm_value, Type.int_8), 'r%d' % )

"""
Computes a LDM instruction.
"""
class Instruction_LDM(Yan85Instruction):
    """
    helper function to call our parse_bin_format function in Yan85Instruction,
    which is somewhat generic to every instructions.
    """
    @staticmethod
    def compute_bin_format():
        return Yan85Instruction.parse_bin_format(yconf.LDM)

    bin_format = compute_bin_format()
    name = "LDM"

    def compute_result(self, *args):
        l.info("compute result called (LDM)")
        l.info(self.data)

"""
Computes a STM instruction.
"""
class Instruction_STM(Yan85Instruction):
    """
    helper function to call our parse_bin_format function in Yan85Instruction,
    which is somewhat generic to every instructions.
    """
    @staticmethod
    def compute_bin_format():
        return Yan85Instruction.parse_bin_format(yconf.STM)

    bin_format = compute_bin_format()
    name = "STM"

    def compute_result(self, *args):
        l.info("compute result called (STM)")
        l.info(self.data)

"""
Computes a ADD instruction.
"""
class Instruction_ADD(Yan85Instruction):
    """
    helper function to call our parse_bin_format function in Yan85Instruction,
    which is somewhat generic to every instructions.
    """
    @staticmethod
    def compute_bin_format():
        return Yan85Instruction.parse_bin_format(yconf.ADD)

    bin_format = compute_bin_format()
    name = "ADD"

    def compute_result(self, *args):
        l.info("compute result called (ADD)")
        l.info(self.data)

"""
Computes a CMP instruction.
"""
class Instruction_CMP(Yan85Instruction):
    """
    helper function to call our parse_bin_format function in Yan85Instruction,
    which is somewhat generic to every instructions.
    """
    @staticmethod
    def compute_bin_format():
        return Yan85Instruction.parse_bin_format(yconf.CMP)

    bin_format = compute_bin_format()
    name = "CMP"

    def compute_result(self, *args):
        l.info("compute result called (CMP)")
        l.info(self.data)

"""
Computes a STK instruction.
"""
class Instruction_STK(Yan85Instruction):
    """
    helper function to call our parse_bin_format function in Yan85Instruction,
    which is somewhat generic to every instructions.
    """
    @staticmethod
    def compute_bin_format():
        return Yan85Instruction.parse_bin_format(yconf.STK)

    bin_format = compute_bin_format()
    name = "STK"

    def compute_result(self, *args):
        l.info("compute result called (STK)")
        l.info(self.data)

"""
Computes a JMP instruction.
"""
class Instruction_JMP(Yan85Instruction):
    """
    helper function to call our parse_bin_format function in Yan85Instruction,
    which is somewhat generic to every instructions.
    """
    @staticmethod
    def compute_bin_format():
        return Yan85Instruction.parse_bin_format(yconf.JMP)

    bin_format = compute_bin_format()
    name = "JMP"

    def compute_result(self, *args):
        l.info("compute result called (JMP)")
        l.info(self.data)

"""
Computes a SYS instruction.
"""
class Instruction_SYS(Yan85Instruction):
    """
    helper function to call our parse_bin_format function in Yan85Instruction,
    which is somewhat generic to every instructions.
    """
    @staticmethod
    def compute_bin_format():
        return Yan85Instruction.parse_bin_format(yconf.SYS)

    bin_format = compute_bin_format()
    name = "SYS"

    def compute_result(self, *args):
        l.info("compute result called (SYS)")
        l.info(self.data)

# list of yan85 instructions.
all_instructions = [
    Instruction_IMM,
    Instruction_LDM,
    Instruction_STM,
    Instruction_ADD,
    Instruction_CMP,
    Instruction_STK,
    Instruction_JMP,
    Instruction_SYS
]

"""
Our lifter class for Yan85.
"""
class Yan85Lifter(GymratLifter):
    instrs = all_instructions

register(Yan85Lifter, 'Yan85')
