from yan85_config import *
from yan85_arch import *
from yan85_lifter import *
from yan85_simos import *
import pyvex
import archinfo

if __name__.__eq__("__main__"):
    # bytecode = bytes([0x4, 0x1, 0x20, 0x8, 0x2, 0x10])
    bts = b""
    with open("./bytecode", "rb") as file:
        for line in file.readlines():
            bts += line

    bytecode = bts

    arch = archinfo.arch_from_id('yan85')
    irsb = pyvex.IRSB(bytecode, 0, arch)

    print(irsb)
