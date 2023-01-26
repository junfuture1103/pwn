import string 

st = ['I','H','M','A','L','A','P']

for ch in string.ascii_uppercase:
    tmp = st
    tmp.insert(6, ch)
    print(''.join(tmp))
    tmp.pop(6)