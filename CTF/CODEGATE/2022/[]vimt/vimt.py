from pwn import *
#p = remote("15.165.92.159", 1234)
p = process("./app")
e = ELF("./app")
# libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")

# gdb.attach(p)

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

def save():
    p.send(b"save"+b"\x0A")

# pause()
#p.recvall()
p.send("A")
# save()

# payload = ""
p.interactive()