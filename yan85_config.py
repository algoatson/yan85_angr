# instructions layout.
# x: arg1, y: opcode, z: arg2
# this allows you to easily change the layout of instructions.
ARG1 = "yyyyyyyy"
ARG2 = "xxxxxxxx"
ARG3 = "zzzzzzzz"

# registers
REG_A = 0x10
REG_B = 0x40
REG_C = 0x20
REG_D = 0x1
REG_S = 0x4
REG_I = 0x8
REG_F = 0x2

# opcodes
IMM = 0x20
LDM = 0x40
STM = 0x1
ADD = 0x2
CMP = 0x10
STK = 0x4
JMP = 0xff
SYS = 0x8

# syscalls
