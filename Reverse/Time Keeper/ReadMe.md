### Description
Time Keeper is a reverse engineering challenge where the flag is calculated based on time-related values. The program appears to show a flag, but it's actually a fake one. The real flag can only be obtained by bypassing the program's anti-debugging protection.

### Challenge Details
- **Category**: Reverse Engineering
- **Difficulty**: Easy to Medium
- **Flag Format**: CMC{...}

### Requirements
- Reverse engineering skills
- Understanding of program flow and execution
- Debugger knowledge
- Time-based encryption understanding

![Challenge GIF](https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExcjFncjRtZjFnajJ4am85emk0ZTFhZTVpMWt4cWhia25nNTRzNWZyMCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/WUUt2ujWlssvUenOuf/giphy.gif)


*Author: xtle0o0*

---


# TimeKeeper Challenge Writeup

## Challenge Overview

TimeKeeper is a binary exploitation challenge where the program provides a fake flag by default but can be manipulated to reveal the real flag. Participants were given only the binary file without source code or Makefile.

## Initial Analysis

When running the binary, we see it simulates processing with delays and then outputs what appears to be a fake flag:

```
Welcome to Time Keeper!
Unlocking the vault...
Processing... 1/3
Processing... 2/3
Processing... 3/3
Vault unlocked! Here's your time-bound key: CMC{F4k3_T1m3_V4lu3_n0w}
```

Using ltrace to examine the program's function calls reveals something interesting:

```bash
┌──(kali㉿kali)-[~/Desktop/citeflag/TimeKeeper]
└─$ ltrace ./time_keeper 
puts("Welcome to Time Keeper!"Welcome to Time Keeper!
)                                                      = 24
puts("Unlocking the vault..."Unlocking the vault...
)                                                       = 23
__printf_chk(2, "Processing... %d/3\n", 1Processing... 1/3
)                                           = 18
fflush(0x7f04d32555c0)                                                               = 0
sleep(1)                                                                             = 0
__printf_chk(2, "Processing... %d/3\n", 2Processing... 2/3
)                                           = 18
fflush(0x7f04d32555c0)                                                               = 0
sleep(1)                                                                             = 0
__printf_chk(2, "Processing... %d/3\n", 3Processing... 3/3
)                                           = 18
fflush(0x7f04d32555c0)                                                               = 0
sleep(1)                                                                             = 0
getenv("TIME_KEEPER_DEBUG_SECRET")                                                   = nil
stpcpy(0x7ffc651e5520, "CMC{")                                                       = 0x7ffc651e5524
strcpy(0x7ffc651e5537, "}")                                                          = 0x7ffc651e5537
__printf_chk(2, "Vault unlocked! Here's your time"...Vault unlocked! Here's your time-bound key: CMC{F4k3_T1m3_V4lu3_n0w}
)                               = 69
+++ exited (status 0) +++
```

The ltrace output reveals a critical piece of information: the program is checking for an environment variable named `TIME_KEEPER_DEBUG_SECRET`, and when it doesn't find it, it displays the fake flag.

## Solution Method 1: Environment Variable

Based on our ltrace discovery, we know the program is looking for an environment variable named `TIME_KEEPER_DEBUG_SECRET`. The expected value isn't directly shown, but common security values like "1", "true", "yes", or dates might work.

Through trial and error (or analysis of the binary's strings and XOR patterns), we discover the value should be `911`.

### How We Discovered the Expected Value

Using GDB to debug the binary, we can set a breakpoint at the `getenv` call and examine what happens:

```bash
──(kali㉿kali)-[~/Desktop/citeflag/TimeKeeper]
└─$ gdb ./time_keeper   

GNU gdb (Debian 16.2-8) 16.2
Copyright (C) 2024 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 188 pwndbg commands and 47 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $base, $hex2ptr, $argv, $envp, $argc, $environ, $bn_sym, $bn_var, $bn_eval, $ida GDB functions (can be used with print/break)                                                                                                                                
Reading symbols from ./time_keeper...

warning: Loadable section ".junk" outside of ELF segments
  in /home/kali/Desktop/citeflag/TimeKeeper/time_keeper
(No debugging symbols found in ./time_keeper)
------- tip of the day (disable with set show-tips off) -------
Want to display each context panel in a separate tmux window? See https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md#splitting--layouting-context
pwndbg> break *0x40147f
Breakpoint 1 at 0x40147f
pwndbg> run
Starting program: /home/kali/Desktop/citeflag/TimeKeeper/time_keeper 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome to Time Keeper!
Unlocking the vault...
Processing... 1/3
Processing... 2/3
Processing... 3/3

Breakpoint 1, 0x000000000040147f in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────
 RAX  0
 RBX  3
 RCX  0x404080 ◂— 0x2020a
 RDX  3
 RDI  0x4041e0 ◂— 'TIME_KEEPER_DEBUG_SECRET'
 RSI  0x4041a0 ◂— 0x313139 /* '911' */
 R8   0
 R9   0
 R10  0x7fffffffdc20 ◂— 1
 R11  0x202
 R12  0x7fffffffddd8 —▸ 0x7fffffffe15f ◂— '/home/kali/Desktop/citeflag/TimeKeeper/time_keeper'
 R13  0x40204b ◂— 'Processing... %d/3\n'
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe310 ◂— 0
 R15  0x403e00 —▸ 0x401330 ◂— endbr64 
 RBP  1
 RSP  0x7fffffffdc50 ◂— 1
 RIP  0x40147f ◂— call getenv@plt
───────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────
 ► 0x40147f    call   getenv@plt                  <getenv@plt>
        name: 0x4041e0 ◂— 'TIME_KEEPER_DEBUG_SECRET'
 
   0x401484    mov    rdi, rax
   0x401487    xor    eax, eax     EAX => 0
   0x401489    test   rdi, rdi
   0x40148c    je     0x4014a2                    <0x4014a2>
 
   0x40148e    lea    rsi, [rip + 0x2d0b]     RSI => 0x4041a0
   0x401495    call   strcmp@plt                  <strcmp@plt>
 
   0x40149a    test   eax, eax
   0x40149c    sete   al
   0x40149f    movzx  eax, al
   0x4014a2    add    rsp, 8
```

Looking at the registers and disassembly:
1. RDI register contains the string "TIME_KEEPER_DEBUG_SECRET" (the parameter to getenv)
2. RSI register is loaded with the value at 0x4041a0, which contains "911"
3. The program then calls strcmp() to compare the environment variable value with "911"

This confirms that "911" is the expected value for the environment variable.

Running the program with this environment variable set:

```bash
TIME_KEEPER_DEBUG_SECRET=911 ./time_keeper
```

Output:
```
Welcome to Time Keeper!
Unlocking the vault...
Processing... 1/3
Processing... 2/3
Processing... 3/3
Vault unlocked! Here's your time-bound key: CMC{tI0mE1kE2pE3rE4t}
```

This reveals the real flag instead of the fake one.

## Solution Method 2: Binary Patching

If we want to bypass the environment check completely, we can patch the binary. First, we need to locate the check in the binary code:

```
┌──(kali㉿kali)-[~/Desktop/citeflag/TimeKeeper]
└─$ objdump -d ./time_keeper | grep getenv
  401012:       74 02                   je     401016 <getenv@plt-0xca>
  401039:       e9 e2 ff ff ff          jmp    401020 <getenv@plt-0xc0>
  ...
  40147f:       e8 5c fc ff ff          call   4010e0 <getenv@plt>
```

We found the call to getenv at address `0x40147f`. Now we examine what happens after this call:

```
┌──(kali㉿kali)-[~/Desktop/citeflag/TimeKeeper]
└─$ objdump -d ./time_keeper | grep -A 20 -B 10 "40147f:"
  ...
  40147f:       e8 5c fc ff ff          call   4010e0 <getenv@plt>
  401484:       48 89 c7                mov    %rax,%rdi
  401487:       31 c0                   xor    %eax,%eax
  401489:       48 85 ff                test   %rdi,%rdi
  40148c:       74 14                   je     4014a2 <sleep@plt+0x322>
  40148e:       48 8d 35 0b 2d 00 00    lea    0x2d0b(%rip),%rsi        # 4041a0 <stdout@GLIBC_2.2.5+0x20>
  401495:       e8 a6 fc ff ff          call   401140 <strcmp@plt>
  40149a:       85 c0                   test   %eax,%eax
  40149c:       0f 94 c0                sete   %al
  40149f:       0f b6 c0                movzbl %al,%eax
  ...
```

The key instruction to patch is at address `0x401487`: `31 c0` (xor %eax,%eax). This sets the return value to 0 by default. If we change this to set the return value to 1, we can bypass the check entirely.

The patch:
```bash
# Change "xor %eax,%eax" (31 c0) to "mov $0x1,%al" (b0 01)
printf '\xb0\x01' | dd of=time_keeper bs=1 seek=5255 count=2 conv=notrunc
```

After applying this patch and running the program:

```
Welcome to Time Keeper!
Unlocking the vault...
Processing... 1/3
Processing... 2/3
Processing... 3/3
Vault unlocked! Here's your time-bound key: CMC{tI0mE1kE2pE3rE4t}
```

We get the real flag without having to set any environment variables.

## Conclusion

TimeKeeper challenged us to bypass a security check to obtain the real flag. We had two viable options:

1. **Environment Variable Method**: Setting `TIME_KEEPER_DEBUG_SECRET=911` to pass the security check legitimately.

2. **Binary Patching Method**: Modifying the binary to always return success from the security check function.

Both methods achieve the same result, revealing the real flag: `CMC{tI0mE1kE2pE3rE4t}`

This challenge demonstrates the importance of understanding how programs check for security conditions and how such checks can be bypassed.
