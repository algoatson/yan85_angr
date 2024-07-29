from archinfo.arch import Arch, Register, Endness
from archinfo.arch import register_arch

class Yan85(Arch):
    memory_endness = Endness.BE
    bits = 8
    vex_arch = None
    name = "Yan85"
    instruction_alignment = 3

    register_list = [
        Register(name='a', size=1, vex_offset=0),
        Register(name='b', size=1, vex_offset=1),
        Register(name='c', size=1, vex_offset=2),
        Register(name='d', size=1, vex_offset=3),
        Register(name='s', size=1, vex_offset=4),
        Register(name='i', size=1, vex_offset=5),
        Register(name='f', size=1, vex_offset=6)
    ]

    ip_offset = 0

    def __init__(self, endness=Endness.BE):
        super().__init__(Endness.BE)

register_arch(["yan85"], 8, Endness.BE, Yan85)
