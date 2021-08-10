# sRSA
`we have created the securest possible rsa algorithm!`

> TLDR: Multiply ciphertext with the modular inverse of e

## Challenge
The challenge provides the following files:

`script.py`
``` python
from Crypto.Util.number import *

p = getPrime(256)
q = getPrime(256)
n = p * q
e = 0x69420

flag = bytes_to_long(open("flag.txt", "rb").read())
print("n =",n)
print("e =", e)
print("ct =",(flag * e) % n)
```

`output.txt`
```
n = 5496273377454199065242669248583423666922734652724977923256519661692097814683426757178129328854814879115976202924927868808744465886633837487140240744798219
e = 431136
ct = 3258949841055516264978851602001574678758659990591377418619956168981354029697501692633419406607677808798749678532871833190946495336912907920485168329153735
```

From the above `script.py`, the ciphertext is derived using:
```
(flag * e) % n
```

Since e and n are given, we can get the flag by multiplying the ciphertext with the modular inverse of e (e<sup>-1</sup>).

POC:
``` python
from Crypto.Util.number import bytes_to_long, long_to_bytes

e = 431136
n = 5496273377454199065242669248583423666922734652724977923256519661692097814683426757178129328854814879115976202924927868808744465886633837487140240744798219
ct = 3258949841055516264978851602001574678758659990591377418619956168981354029697501692633419406607677808798749678532871833190946495336912907920485168329153735

e_inverse = pow(e, -1, n) # available on python 3.8+
plaintext = (ct * e_inverse) % n
print("Flag: " + long_to_bytes(plaintext).decode())
```

Output of the script:
``` bash
$ python3 crypto1.py                      
Flag: rarctf{ST3GL0LS_ju5t_k1dd1ng_th1s_w4s_n0t_st3g_L0L!_83b7e829d9}
```

Flag: `rarctf{ST3GL0LS_ju5t_k1dd1ng_th1s_w4s_n0t_st3g_L0L!_83b7e829d9}`