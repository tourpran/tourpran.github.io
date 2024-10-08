---
title: "Global Offset Table and Procedure Linkage Table"
date: 2020-09-06
draft: false
tags: ["short-blog", "pwn", "GOT"]
layout: "background"
---

How do programs know where the libc functions are in the libc, How is the internal implementation of the same ? We will look into GOT and PLT in short in this one.
<!--more--> 

## where and why ?

> So Before diving into the concepts and working of GOT and PLT. Lets understand why we need them and where we need them. 

So, In modern days we cant always compile the libraries or dependencies along with the binary. So the alternative option is to use Dynamic Linking. With advantages comes some complexity :P. So we dont know the address of functions that are used in the binary which are indeed defined in the dependency. So each time the binary runs the address needs to be ``resolved``. This cool process is done with the help of GOT and PLT. Also these are not functions. They are just tables as the names suggest.

## Sample Code 

```c
#include <stdio.h>
int main()
{
	printf("Hello World\n");
	printf("Welcome to my blog\n");
}
```
now compile this with no pie and 64 bit for further ease.
```
gcc test.c -o test -no-pie
```

Now this is Dynamically Linked (GCC does Dynamic Linking by default). So lets us run this... Works fine.

## GDB Code Analysis

So let us use GDB (me - GDB-PEDA). Now disassemble the main and check for printf that we implemented. Hmm.. Weird We dont see it. If you read my previous blog you would know why. In short this is for efficiency. Do notice that the puts is actually termed puts@plt. 
* Set a breakpoint at puts@plt
* run the program
We come to puts@plt instead of next step let us single step to see what is there in the puts@plt. 
![](/images/got_and_plt_short_blog/got1.png)

Now in the disassembly we can see that its not really puts function, We landed in the plt section of puts. Yes!! Procedure Linkage **Table**. Its basically a table which does a jump to the Global Offset Table for that particular entry, "puts". Also remember this "GOT" is located in the .got section in the binary.

Now we know that the got will not be filled with the address of puts as this is the first time this LIBC function is being called. So instead of real address of puts the got section of puts will contain the address of next instruction, which is a push followed by another jump. This push of a number **can** be imagined as the index of the string "puts" in the string table. Next the jump is to the function ``_dl_runtime_resolve``. Yes this is the resolver, 

> dl runtime resolve 

This function will take the string as input and will find the real address of puts in libc and finally will change the GOT entry for puts. So due to this the function puts need not be searched again in the libc but can be directly taken from the got.

This whole process can be imagined this way.
![](/images/got_and_plt_short_blog/got2.png)

## end
End of story. Great now you know a little bit of how GOT and PLT works.

{{< youtube E2-E_fQ13Xs >}}