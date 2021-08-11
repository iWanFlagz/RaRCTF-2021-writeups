---
grand_parent: Categories
parent: Crypto
title: minigen
nav_order: 1
---

# minigen 
```
A stream cipher in only 122 bytes!

Note: This has been tested on python versions 3.8 and 3.9
```

## Challenge

> TL;DR: Figure out the value of `next(g)` (key) used to encrypt its corresponding plaintext's byte. Then, xor `next(g)` with the ciphertext to get the flag.  

We are given the following ciphertext:
```
281 547 54 380 392 98 158 440 724 218 406 672 193 457 694 208 455 745 196 450 724
```

And the source code:
``` python
exec('def f(x):'+'yield((x:=-~x)*x+-~-x)%727;'*100)
g=f(id(f));print(*map(lambda c:ord(c)^next(g),list(open('f').read())))
```

The recurrence relation to generate each of the key is `key[i] =  key[i - 1] + (key[i - 1] - key[i - 2] + 2)`

From the above recurrence relation, it is clear that we need to know at least the first two keys used to encrypt the plaintext. Since the flag starts with `rarctf`, we can obtain the first two keys:

``` python
>>> ord('r') ^ 281
363
>>> ord('a') ^ 547
578
```

Once we have obtained the keys used to encrypt the plaintext, we xor the key with its corresponding ciphertext to get the flag.

Working POC:
```python
arr = [281, 547, 54, 380, 392, 98, 158, 440, 724, 218, 406, 672, 193, 457, 694, 208, 455, 745, 196, 450, 724]

g = [363, 578]

def crack_gen():
    for i in range(1, 20):
        diff = g[i] - g[i - 1]
        next_gen = (g[i] + diff + 2) % 727 
        g.append(next_gen)

def get_flag():
    for i in range(len(arr)):
        print(chr(arr[i] ^ g[i]), end="")

crack_gen()
print("Flag: ", end="")
get_flag()
```

Output of the script:
```bash
$ python3 crypto.py
Flag: rarctf{pyg01f_1s_fun}
```

Flag: `rarctf{pyg01f_1s_fun}`