# Password Cracking Simulator
### Educational Cybersecurity Project

> ⚠️ **For educational and research purposes only.**

---

## Project Structure

```
password_cracker/
├── password_cracker.py       ← Core Python simulator (CLI)
├── test_password_cracker.py  ← Test suite (21 tests)
└── visualizer.html           ← Interactive browser-based UI
```

---

## Features

### 1. Password Hashing
- Algorithms: **MD5**, **SHA-1**, **SHA-256**, **SHA-512**
- Salted hashing (prevents rainbow table attacks)
- All via Python's built-in `hashlib` — no external dependencies

### 2. Brute Force Attack
- Exhaustive search over configurable character sets
- Configurable max password length
- Reports: attempts, time taken, speed (hashes/sec)
- **Complexity**: O(|Σ|ⁿ) — exponential in password length

### 3. Dictionary Attack
- Built-in wordlist of 100 most common passwords
- Mutation engine: UPPER, Title, reverse, leet-speak, digit/symbol appends
- Pre-computed hash tables for fast lookup
- **Complexity**: O(W × M) — linear in words × mutations

### 4. Time Complexity Analysis
- Theoretical worst-case table across charset sizes and lengths
- Big-O comparison: brute force vs dictionary vs rainbow table vs salted
- Interactive calculator in the browser visualizer

### 5. Password Strength Meter (Visualizer)
- Entropy calculation: n × log₂(|Σ|)
- 8-point checklist (length, character classes, common passwords, repeats)
- Crack time estimates at 4 different attacker speeds

---

## Usage

### Run the interactive CLI:
```bash
python password_cracker.py
```

### Run the full simulation:
```bash
python password_cracker.py --simulate
```

### Run the test suite:
```bash
python test_password_cracker.py
```

### Browser Visualizer:
Open `visualizer.html` in any modern browser — no server needed.

---

## Key Concepts Demonstrated

| Concept | Where |
|---|---|
| Deterministic hashing | Hash Lab tab |
| Why salting matters | Hash Lab + Collision demo |
| Exponential growth of brute force | Brute Force tab + Complexity tab |
| Dictionary + mutation attacks | Dictionary tab |
| Entropy formula | Strength Meter tab |
| Defence recommendations | Complexity tab |

---

## Dependencies
- Python 3.6+ standard library only (`hashlib`, `itertools`, `string`, `time`)
- Browser visualizer: vanilla JS + Web Crypto API (built into all modern browsers)

---

## Defences Covered
- ✅ Use Argon2id / bcrypt / scrypt (adaptive slow hashes)
- ✅ Minimum 12+ characters
- ✅ Large character sets (upper + lower + digits + symbols)
- ✅ Unique random salts per password
- ✅ Rate limiting and account lockout
- ❌ Never store plaintext passwords
- ❌ Avoid MD5 / SHA-1 for passwords
