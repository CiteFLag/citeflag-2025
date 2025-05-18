## Challenge Description

### Overview
A mysterious hidden service on the Tor network contains a flag, but normal inspection methods are disabled. Navigate the layers of protection to find what's hidden within.

### Challenge Details
- **Category**: Misc
- **Difficulty**: Easy
- **Flag Format**: `CMC{}`

### Requirements
- Tor Browser
- Knowledge of alternative source viewing methods
- No onion cutting skills required

![Challenge GIF](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExdWRhamNpZ2I5dTRpc2FiazV4aDYzaWJlN2pvY256YTlyb3d5bnN2cyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/0qliEJnbGZNFM7yaNZ/giphy.gif)

*Author: xtle0o0*

---

## Solution Guide

### Step 1: Initial Access
Accessing the provided URL using Tor Browser reveals the challenge interface:
![Initial View](../assets/{7CE771F2-9C74-4D1C-9A52-0AFBEEEE88B4}.png)

### Step 2: Inspection Attempts
Attempting to use standard inspection methods (Ctrl+U or F12) triggers the site's protection:
![Protection Response](../../assets/image.png)

### Step 3: JavaScript Disabling
Disabling JavaScript return this:
![JS Disabled View](../../assets/GTYGCBJSDC.png)

### Step 4: Source Code Analysis
You can either:
- Use the view-source protocol directly: `view-source:http://lozlfz4jeailhjv77mq6rgmslosvjk5re7kvdjaed6amtaea7ol2ixid.onion/`
- Or access the source code after disabling JavaScript

### Step 5: Flag Discovery
Searching for 'CMC' in the page source reveals the hidden flag:
![Flag Location](../../assets/JCSDCHSDCSDBJC.png)

### Flag
```CMC{0n10n_l4y3r5_4r3_t45ty}```