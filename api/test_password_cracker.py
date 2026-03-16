"""
Test Suite — Password Cracking Simulator
Run:  python test_password_cracker.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from password_cracker import (
    hash_password, hash_with_salt,
    brute_force_attack, dictionary_attack,
    build_hash_table, DEFAULT_WORDLIST,
    SUPPORTED_ALGORITHMS,
)

PASS_MARK = "  ✓ PASS"
FAIL_MARK = "  ✗ FAIL"
results = []

def test(name, condition):
    status = PASS_MARK if condition else FAIL_MARK
    print(f"{status}  {name}")
    results.append(condition)

print("\n" + "═"*55)
print("  RUNNING TEST SUITE")
print("═"*55)

# ── Hashing ───────────────────────────────────────────────
print("\n  [Hashing]")

h = hash_password("password123", "sha256")
test("SHA-256 produces 64-char hex string", len(h) == 64)

h2 = hash_password("password123", "md5")
test("MD5 produces 32-char hex string", len(h2) == 32)

test("Same password → same hash (deterministic)", hash_password("hello") == hash_password("hello"))
test("Different passwords → different hashes", hash_password("hello") != hash_password("world"))

test("Salt changes the hash", hash_with_salt("pass","ABC") != hash_with_salt("pass","XYZ"))
test("Salted hash ≠ unsalted hash", hash_with_salt("pass","SALT") != hash_password("pass"))

# All algorithms work
for algo in SUPPORTED_ALGORITHMS:
    test(f"Algorithm '{algo}' supported", len(hash_password("test", algo)) > 0)

# ── Brute Force ───────────────────────────────────────────
print("\n  [Brute Force]")

import string

# Crack "ab" in digits+lowercase, max_len=2
target_ab = hash_password("ab")
res = brute_force_attack(target_ab, "sha256", string.ascii_lowercase, 3, verbose=False)
test("Brute force finds 'ab'", res["found"] and res["password"] == "ab")
test("Brute force attempt count > 0", res["attempts"] > 0)
test("Brute force time_taken ≥ 0", res["time_taken"] >= 0)

# Crack "5" in digits
target_5 = hash_password("5")
res2 = brute_force_attack(target_5, "sha256", string.digits, 1, verbose=False)
test("Brute force finds single digit '5'", res2["found"] and res2["password"] == "5")

# Should NOT find "xyz" in digits-only charset
target_xyz = hash_password("xyz")
res3 = brute_force_attack(target_xyz, "sha256", string.digits, 4, verbose=False)
test("Brute force returns found=False when not in charset", not res3["found"])

# ── Dictionary Attack ─────────────────────────────────────
print("\n  [Dictionary Attack]")

target_pw = hash_password("password")
res4 = dictionary_attack(target_pw, verbose=False)
test("Dict attack finds 'password'", res4["found"] and res4["password"] == "password")

target_admin = hash_password("admin")
res5 = dictionary_attack(target_admin, verbose=False)
test("Dict attack finds 'admin'", res5["found"])

# Mutation test — "password1" should be found via mutations
target_m = hash_password("password1")
res6 = dictionary_attack(target_m, verbose=False)
test("Dict attack finds mutated 'password1'", res6["found"])

# Strong password should NOT be found
target_strong = hash_password("Xk#9mP!qZ2")
res7 = dictionary_attack(target_strong, verbose=False)
test("Dict attack fails on strong password", not res7["found"])

# ── Rainbow Table ─────────────────────────────────────────
print("\n  [Rainbow Table / Hash Table]")

table = build_hash_table(DEFAULT_WORDLIST[:10])
test("Hash table built correctly", isinstance(table, dict) and len(table) == 10)

first_word = DEFAULT_WORDLIST[0]
first_hash = hash_password(first_word)
test("Hash table lookup succeeds", table.get(first_hash) == first_word)

# ── Summary ───────────────────────────────────────────────
print("\n" + "═"*55)
passed = sum(results)
total  = len(results)
print(f"  Results: {passed}/{total} tests passed", end="")
if passed == total:
    print("  🎉 All tests passed!")
else:
    print(f"  ⚠ {total - passed} test(s) failed.")
print("═"*55 + "\n")
