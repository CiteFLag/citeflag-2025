#### Challenge Details

* **Category:** Crypto
* **Difficulty:** easy
* **Goal:** Undo the “leet-ification” on a Base64 payload, then decode to reveal `CMC{…}`.

---

#### Given Ciphertext

```
CMC{bGVldF9j4HF5bGVuZ2Vf4XMfZnVu}
```

---

#### 1. Strip Off the Wrapper

Remove the leading `CMC{` and trailing `}`:

```
bGVldF9j4HF5bGVuZ2Vf4XMfZnVu
```

---

#### 2. Reverse the “Leet” Substitutions

In this challenge, two chunks of the Base64 string were replaced:

* `4HF5b` → `aGFsb`
* `4XMf`  → `aXNf`

Apply those replacements:

```
bGVldF9j**4HF5b**GVuZ2Vf**4XMf**ZnVu
   ↓        ↓
bGVldF9j**aGFsb**GVuZ2Vf**aXNf**ZnVu
```

Resulting in a valid Base64 string:

```
bGVldF9jaGFsbGVuZ2VfaXNfZnVu
```

---

#### 3. Base64-Decode the Restored String

Run:

```bash
echo 'bGVldF9jaGFsbGVuZ2VfaXNfZnVu' | base64 -d
```

You’ll get:

```
leet_challenge_is_fun
```

---

#### 4. Reconstruct the Flag

Wrap the decoded text in `CMC{…}`:

```
CMC{leet_challenge_is_fun}
```

---

**Final Flag:** `CMC{leet_challenge_is_fun}`
