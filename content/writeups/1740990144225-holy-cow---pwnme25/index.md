---
title: "holy cow - pwnme25"
date: 2025-03-03
draft: false
description: "a description"
tags: ["example", "tag"]
---

## Introduction:

This is the writeup for the pwnmeCTF 2025 challenge called ``holy cow revenge²``. Without wasting much time lets get right into it.
<!--more-->

### The lore:
![alt text](image.png)

This challenge is not about the cow itself but we are talking about the `hole` in javascript engine called `v8`. This challenge was a revenge of the already existing challenge called [holy cow](https://ruulian.me/post/FCSC2024-holy-cow) ofcourse. 

What happened ? The author forgot to remove the `d8` builtins. So people sovled it within few minutes of the ctf starting. My stupid brain thought everyone had a nday/ zeroday in their hand to solve ctf challenges. :P

This is how ``holy cow revenge²`` was born. 

Also I am still learning browser exploitation and this is my attempt to understand what exactly is going on in this vulnerability. I solved it only after the ctf because my tiny brain could'nt figure out how to mess up the range analysis in time. But enough ranting time to understand some v8.

### The patch:

```c
+BUILTIN(SetPrototypeHole) {
+  HandleScope scope(isolate);
+  return ReadOnlyRoots(isolate).hash_table_hole_value();
+}
+
```
This is as straight forward as it can get. This leaks the value of the `hole` itself. How is this dangerous ? Read [this to get a better understanding](https://starlabs.sg/blog/2022/12-the-hole-new-world-how-a-small-leak-will-sink-a-great-browser-cve-2021-38003/#corrupting-map-size).


```c
+
+  // BUG: I saw some guis doing weird stuff with this ...
+  CSA_CHECK(this, SmiGreaterThanOrEqual(CAST(LoadObjectField(table, OrderedHashMap::NumberOfElementsOffset())), SmiConstant(0)));
+
```
> This part of the patch checks if your `number of elements` for the map is greater than `0`, during a element insertion (`MapPrototypeSet`). This is what prevents you from using the previous `holy cow` challenge. Since the old exploit keeps abusing the map. (poor map).