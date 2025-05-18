## Challenge Details
- **Category**: Web
- **Difficulty**: Medium

## Description
Fractured Authority is a web application with broken access control mechanisms and JWT authentication vulnerabilities. Your mission is to exploit the weaknesses in the JWT implementation and authorization system to gain elevated privileges and capture the flag.

## Requirements
- Understanding of JWT (JSON Web Tokens)
- Knowledge of JWT security vulnerabilities
- Authorization bypass techniques
- Web security testing skills
- Node.js application security

## Important Note
The JWT secret used in this application comes from a common wordlist (rockyou.txt). Can you figure out what it is?

## Login Credentials
- Regular user: `user` / `password123`

## Flag Format
The flag is split into two parts that need to be combined:
- First part: `CMC{XXX_XXXX_XXXXXXXXXX`
- Second part: `_XXX_XXXX_XXXXXX}`

## Challenge Overview
This CTF challenge focuses on exploiting JWT and access control vulnerabilities:

1. Part 1: Analyze the JWT implementation
2. Part 2: Discover the weak JWT secret
3. Part 3: Forge admin tokens to bypass authorization
4. Part 4: Retrieve both parts of the flag from protected admin endpoints

---

*Author: xtle0o0*

---

## Solution Walkthrough

### Finding the JWT Secret

The challenge description suggests that we need to abuse JWT tokens and forge admin tokens to bypass authorization. Let's start by logging in with the regular user credentials to obtain a token:

![Login Screen](../../assets/{FA305A4D-98D2-4C10-B8A9-423A1278AB60}.png)

Next, I'll try to crack the JWT secret using a brute force attack with the rockyou.txt wordlist:

![JWT Cracking](../../assets/{5B4DB302-6D73-415A-85FC-9295B97D1E04}.png)

We can see that the secret is `superman`. Now I can reconstruct a new JWT token using CyberChef to elevate our privileges:

![JWT Token Creation](../../assets/{DCC8164A-3F97-47C1-A520-C4DAD651E3EA}.png)

The new JWT token is:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNzQ3NTU3NjQzfQ._SHlgSyKlx_fnPI38MhPaaI9efwEg4SOJoGkh7R7bG0
```

### Accessing the Admin Panel

Let's replace the original token with our forged one and refresh the page:

![Admin Panel Access](../../assets/{BD8592FA-EEDB-4312-B70B-6C0D51D462E3}.png)

Success! We now have admin privileges.

### Retrieving the First Part of the Flag

The site suggests going to the admin panel. Once there, clicking on "Get Secret Data" reveals:

![Secret Data](../../assets/{97DE07E2-13E0-4372-B10F-4A34298031F2}.png)

We receive a string: `"JDJrC^]V=EN9VJ9GO\<89G"`

This looks like it might be encoded, but it's not from the base family (base64, base85, etc.). It appears to be XOR-encoded data, but we don't know the key. Let's brute force it:

![XOR Brute Force](../../assets/{98A429D3-EF8A-4E56-8948-F28EB0C08E4E}.png)

With key 9, we get the first part of the flag: `CMC{JWT_4LG0_C0NFU510N`

### Finding the Second Part of the Flag

The hint suggests: "This is only the first part of the flag. Look elsewhere for the second part..."

Let's examine the page source code:

```html
<!DOCTYPE html>
<html lang="en">
<!-- ... HTML content ... -->
  <script>
    // Check if user is admin
    async function checkAdmin() {
      try {
        const response = await fetch('/api/user');
        if (response.ok) {
          const userData = await response.json();
          if (!userData.isAdmin) {
            window.location.href = '/dashboard';
          } else {
            // If admin, fetch and store the second part of the flag
            storeSecondPartFlag();
          }
        } else {
          window.location.href = '/login';
        }
      } catch (error) {
        console.error('Error:', error);
        window.location.href = '/login';
      }
    }

    // Store second part of the flag in localStorage
    async function storeSecondPartFlag() {
      try {
        const response = await fetch('/api/admin/init');
        if (response.ok) {
          const data = await response.json();
          if (data.secondPartFlag) {
            localStorage.setItem('adminData', data.secondPartFlag);
          }
        }
      } catch (error) {
        console.error('Error storing flag part:', error);
      }
    }
    // ... more JavaScript ...
  </script>
</body>
</html>
```

We discover that the second part of the flag is silently retrieved from the `/api/admin/init` endpoint and stored in the browser's localStorage:

![Local Storage](../../assets/{176A1BDC-1C02-4D00-A510-90857BC57AB9}.png)

The value stored in localStorage is `sHbXskGH_sIGWfGh3`.  it was ROT47 cipher with key 74:

![ROT47 Decryption](../../assets/{AB1261E9-E0EA-48A0-AE04-852A7928A431}.png)

The decrypted value is: `_4ND_W34K_53CR3T}`

## Complete Flag

Combining both parts of the flag:

`CMC{JWT_4LG0_C0NFU510N_4ND_W34K_53CR3T}` 