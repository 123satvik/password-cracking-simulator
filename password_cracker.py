"""
╔══════════════════════════════════════════════════════════════╗
║          PASSWORD CRACKING SIMULATOR - CyberSec Lab          ║
║     Educational tool for understanding attack vectors        ║
╚══════════════════════════════════════════════════════════════╝

Modules:
  - Password Hashing (MD5, SHA1, SHA256, bcrypt)
  - Brute Force Attack
  - Dictionary Attack
  - Time Complexity Analysis
"""

import hashlib
import itertools
import string
import time
import os
import json
from datetime import datetime


# ─────────────────────────────────────────────
#  1.  PASSWORD HASHING
# ─────────────────────────────────────────────

SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]

def hash_password(password: str, algorithm: str = "sha256") -> str:
    """Hash a plaintext password using the specified algorithm."""
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm. Choose from: {SUPPORTED_ALGORITHMS}")
    h = hashlib.new(algorithm)
    h.update(password.encode("utf-8"))
    return h.hexdigest()


def hash_with_salt(password: str, salt: str, algorithm: str = "sha256") -> str:
    """Hash password with a salt (salted hashing)."""
    salted = salt + password
    return hash_password(salted, algorithm)


def demonstrate_hashing():
    """Showcase how the same password looks under different algorithms."""
    print("\n" + "═"*60)
    print("  [1] PASSWORD HASHING DEMONSTRATION")
    print("═"*60)

    test_passwords = ["password123", "admin", "P@$$w0rd!", "hello"]

    for pwd in test_passwords:
        print(f"\n  Password : '{pwd}'")
        for algo in SUPPORTED_ALGORITHMS:
            digest = hash_password(pwd, algo)
            print(f"  {algo.upper():8s}: {digest}")

    # Salt demonstration
    print("\n" + "─"*60)
    print("  SALT DEMONSTRATION  (same password, different salts)")
    print("─"*60)
    pwd = "password123"
    for salt in ["ABC", "XYZ", "RAND"]:
        digest = hash_with_salt(pwd, salt)
        print(f"  Salt='{salt}' → {digest}")


# ─────────────────────────────────────────────
#  2.  BRUTE FORCE ATTACK
# ─────────────────────────────────────────────

def brute_force_attack(
    target_hash: str,
    algorithm: str = "sha256",
    charset: str = string.ascii_lowercase,
    max_length: int = 4,
    verbose: bool = True,
) -> dict:
    """
    Attempt to crack a hash by trying every possible combination.

    Returns a result dictionary with:
      - found       : bool
      - password    : str | None
      - attempts    : int
      - time_taken  : float (seconds)
      - speed       : float (hashes/sec)
    """
    start_time = time.perf_counter()
    attempts = 0

    if verbose:
        print(f"\n  Target hash : {target_hash[:32]}...")
        print(f"  Algorithm   : {algorithm.upper()}")
        print(f"  Charset     : {len(charset)} chars  ({charset[:20]}{'...' if len(charset)>20 else ''})")
        print(f"  Max length  : {max_length}")
        total_space = sum(len(charset) ** l for l in range(1, max_length + 1))
        print(f"  Search space: {total_space:,} combinations")
        print()

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            candidate_hash = hash_password(candidate, algorithm)
            attempts += 1

            if candidate_hash == target_hash:
                elapsed = time.perf_counter() - start_time
                speed = attempts / elapsed if elapsed > 0 else float("inf")
                if verbose:
                    print(f"  ✓ CRACKED!  Password = '{candidate}'")
                    print(f"  Attempts   : {attempts:,}")
                    print(f"  Time       : {elapsed:.4f}s")
                    print(f"  Speed      : {speed:,.0f} hashes/sec")
                return {
                    "found": True,
                    "password": candidate,
                    "attempts": attempts,
                    "time_taken": elapsed,
                    "speed": speed,
                }

            if verbose and attempts % 10000 == 0:
                elapsed = time.perf_counter() - start_time
                print(f"  … {attempts:>10,} attempts | current: '{candidate}' | {elapsed:.1f}s")

    elapsed = time.perf_counter() - start_time
    speed = attempts / elapsed if elapsed > 0 else float("inf")
    if verbose:
        print(f"  ✗ Not found in search space.")
        print(f"  Attempts   : {attempts:,}")
        print(f"  Time       : {elapsed:.4f}s")
    return {
        "found": False,
        "password": None,
        "attempts": attempts,
        "time_taken": elapsed,
        "speed": speed,
    }


def demonstrate_brute_force():
    """Demo brute force on short, simple passwords."""
    print("\n" + "═"*60)
    print("  [2] BRUTE FORCE ATTACK DEMONSTRATION")
    print("═"*60)

    test_cases = [
        ("ab",  string.ascii_lowercase, 3),
        ("123", string.digits,          4),
        ("ace", string.ascii_lowercase, 3),
    ]

    for pwd, charset, max_len in test_cases:
        target = hash_password(pwd)
        print(f"\n  Cracking: '{pwd}'  →  SHA-256")
        result = brute_force_attack(target, "sha256", charset, max_len)
        if result["found"]:
            print(f"  Complexity: O(|Σ|^n) = O({len(charset)}^{max_len}) = O({len(charset)**max_len:,})")


# ─────────────────────────────────────────────
#  3.  DICTIONARY ATTACK
# ─────────────────────────────────────────────

# Built-in wordlist (top 100 most common passwords)
DEFAULT_WORDLIST = [
    "password", "123456", "password123", "admin", "letmein", "qwerty",
    "abc123", "monkey", "master", "dragon", "111111", "baseball", "iloveyou",
    "trustno1", "sunshine", "princess", "welcome", "shadow", "superman",
    "michael", "batman", "passw0rd", "696969", "ashley", "mustang",
    "access", "hello", "charlie", "donald", "football", "jennifer",
    "ninja", "ginger", "joshua", "pepper", "thomas", "tigger", "soccer",
    "computer", "starwars", "matrix", "jesus", "hockey", "ranger",
    "hunter", "george", "jordan", "harley", "ranger", "dakota",
    "buster", "cheese", "cowboy", "amanda", "andrew", "robert",
    "flower", "summer", "joseph", "bailey", "jessica", "william",
    "daniel", "zxcvbn", "austin", "thunder", "taylor", "matrix",
    "wizard", "hammer", "silver", "guitar", "online", "killer",
    "gators", "magnum", "winter", "boomer", "yankee", "justin",
    "diablo", "viking", "hotdog", "pepper", "gandalf", "winter",
    "coffee", "purple", "batman", "random", "qazwsx", "1q2w3e",
    "pass", "love", "money", "test", "game", "play", "king",
    "rock", "fire", "blue",
]


def build_hash_table(wordlist: list, algorithm: str = "sha256") -> dict:
    """Pre-compute a hash table (rainbow table) for fast lookups."""
    return {hash_password(w, algorithm): w for w in wordlist}


def dictionary_attack(
    target_hash: str,
    wordlist: list = [],
    algorithm: str = "sha256",
    use_mutations: bool = True,
    verbose: bool = True,
) -> dict:
    """
    Dictionary attack: tries words from a wordlist + common mutations.

    Mutations applied:
      - Original, UPPER, Title, reverse
      - Append digits 0-9, 00-99
      - Prepend/append special chars
      - leet-speak substitutions
    """
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST

    candidates = []

    def add(w):
        candidates.append(w)

    LEET = str.maketrans("aeiost", "4310$+")

    for word in wordlist:
        add(word)
        add(word.upper())
        add(word.capitalize())
        add(word[::-1])
        add(word.translate(LEET))
        if use_mutations:
            for d in range(10):
                add(f"{word}{d}")
                add(f"{d}{word}")
            for d in range(10, 100):
                add(f"{word}{d}")
            for sym in ["!", "@", "#", "$", "*", "123", "!"]:
                add(f"{word}{sym}")
                add(f"{sym}{word}")

    # De-duplicate while preserving order
    seen = set()
    unique_candidates = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique_candidates.append(c)

    start_time = time.perf_counter()
    attempts = 0

    if verbose:
        print(f"\n  Target hash    : {target_hash[:32]}...")
        print(f"  Algorithm      : {algorithm.upper()}")
        print(f"  Wordlist size  : {len(wordlist):,} base words")
        print(f"  With mutations : {len(unique_candidates):,} candidates")
        print()

    for candidate in unique_candidates:
        candidate_hash = hash_password(candidate, algorithm)
        attempts += 1

        if candidate_hash == target_hash:
            elapsed = time.perf_counter() - start_time
            speed = attempts / elapsed if elapsed > 0 else float("inf")
            if verbose:
                print(f"  ✓ CRACKED!  Password = '{candidate}'")
                print(f"  Attempts   : {attempts:,}")
                print(f"  Time       : {elapsed:.4f}s")
                print(f"  Speed      : {speed:,.0f} hashes/sec")
            return {
                "found": True,
                "password": candidate,
                "attempts": attempts,
                "time_taken": elapsed,
                "speed": speed,
                "method": "dictionary",
            }

    elapsed = time.perf_counter() - start_time
    speed = attempts / elapsed if elapsed > 0 else float("inf")
    if verbose:
        print(f"  ✗ Not found in dictionary.")
        print(f"  Attempts   : {attempts:,}")
        print(f"  Time       : {elapsed:.4f}s")

    return {
        "found": False,
        "password": None,
        "attempts": attempts,
        "time_taken": elapsed,
        "speed": speed,
        "method": "dictionary",
    }


def demonstrate_dictionary():
    """Demo dictionary attack on common and mutated passwords."""
    print("\n" + "═"*60)
    print("  [3] DICTIONARY ATTACK DEMONSTRATION")
    print("═"*60)

    test_passwords = ["password", "admin123", "dragon!", "Monkey1", "p4$$w0rd"]

    for pwd in test_passwords:
        target = hash_password(pwd)
        print(f"\n  Cracking: '{pwd}'")
        result = dictionary_attack(target, verbose=True)
        if not result["found"]:
            print(f"  (Not in dictionary — would require brute force)")


# ─────────────────────────────────────────────
#  4.  TIME COMPLEXITY ANALYSIS
# ─────────────────────────────────────────────

def time_complexity_analysis():
    """
    Analyse and display theoretical & practical time complexity
    for both attack types across charset sizes and password lengths.
    """
    print("\n" + "═"*60)
    print("  [4] TIME COMPLEXITY ANALYSIS")
    print("═"*60)

    charsets = {
        "digits only (0-9)":          10,
        "lowercase alpha (a-z)":       26,
        "lower + digits":              36,
        "lower + upper":               52,
        "alphanumeric":                62,
        "full printable ASCII":        95,
    }

    HASH_RATE = 1_000_000  # realistic software hashing speed (1M hashes/sec)

    print(f"\n  Assumed hash rate : {HASH_RATE:,} hashes/second (software SHA-256)")
    print(f"  {'Charset':<30} {'Len':>4}  {'Combinations':>20}  {'Time (worst)':>16}")
    print("  " + "─"*78)

    for name, size in charsets.items():
        for length in [4, 6, 8, 10]:
            combos = size ** length
            seconds = combos / HASH_RATE
            human_time = _human_time(seconds)
            print(f"  {name:<30} {length:>4}  {combos:>20,}  {human_time:>16}")
        print()

    # Big-O summary
    print("  " + "─"*78)
    print("  THEORETICAL COMPLEXITY:")
    print()
    print("  Brute Force  : O(|Σ|ⁿ)  — exponential in password length n")
    print("                 where |Σ| = charset size")
    print()
    print("  Dict Attack  : O(W × M) — linear in wordlist × mutations")
    print("                 where W = word count, M = mutation factor")
    print()
    print("  Rainbow Table: O(1) lookup  (trade space for time)")
    print("  Salted Hash  : Defeats rainbow tables → back to O(|Σ|ⁿ)")
    print()
    print("  Best Defence : long passwords + large charset + salting + bcrypt/Argon2")


def _human_time(seconds: float) -> str:
    """Convert seconds to a human-readable duration string."""
    if seconds < 0.001:
        return f"{seconds*1000:.2f} ms"
    if seconds < 1:
        return f"{seconds:.4f} sec"
    if seconds < 60:
        return f"{seconds:.2f} sec"
    if seconds < 3600:
        return f"{seconds/60:.2f} min"
    if seconds < 86400:
        return f"{seconds/3600:.2f} hrs"
    if seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    years = seconds / 31536000
    if years < 1e6:
        return f"{years:.2e} yrs"
    return f"{years:.2e} yrs"


# ─────────────────────────────────────────────
#  5.  FULL SIMULATION
# ─────────────────────────────────────────────

def full_simulation():
    """
    Run the complete cracking simulation:
    hashing → dictionary → brute force → time analysis.
    """
    print("\n" + "█"*60)
    print("  PASSWORD CRACKING SIMULATOR — Full Simulation")
    print("  " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("█"*60)

    demonstrate_hashing()
    demonstrate_dictionary()
    demonstrate_brute_force()
    time_complexity_analysis()

    print("\n" + "═"*60)
    print("  SIMULATION COMPLETE")
    print("  ⚠  For educational purposes only.")
    print("═"*60 + "\n")


# ─────────────────────────────────────────────
#  6.  INTERACTIVE MODE (CLI)
# ─────────────────────────────────────────────

MENU = """
╔══════════════════════════════════╗
║   PASSWORD CRACKING SIMULATOR   ║
╠══════════════════════════════════╣
║  1. Hash a password              ║
║  2. Brute force attack           ║
║  3. Dictionary attack            ║
║  4. Time complexity analysis     ║
║  5. Run full simulation          ║
║  0. Exit                         ║
╚══════════════════════════════════╝
"""

def interactive():
    """CLI interactive menu."""
    while True:
        print(MENU)
        choice = input("  Select option: ").strip()

        if choice == "0":
            print("\n  Goodbye!\n")
            break

        elif choice == "1":
            pwd = input("  Enter password: ")
            for algo in SUPPORTED_ALGORITHMS:
                print(f"  {algo.upper():8s}: {hash_password(pwd, algo)}")

        elif choice == "2":
            pwd = input("  Enter password to crack: ")
            algo = input("  Algorithm [sha256]: ").strip() or "sha256"
            target = hash_password(pwd, algo)
            max_len = int(input("  Max length [4]: ").strip() or "4")
            cs_choice = input("  Charset  (1=digits 2=lower 3=lower+digits) [2]: ").strip() or "2"
            cs_map = {"1": string.digits, "2": string.ascii_lowercase, "3": string.ascii_lowercase + string.digits}
            charset = cs_map.get(cs_choice, string.ascii_lowercase)
            brute_force_attack(target, algo, charset, max_len)

        elif choice == "3":
            pwd = input("  Enter password to crack: ")
            algo = input("  Algorithm [sha256]: ").strip() or "sha256"
            target = hash_password(pwd, algo)
            dictionary_attack(target, algorithm=algo)

        elif choice == "4":
            time_complexity_analysis()

        elif choice == "5":
            full_simulation()

        else:
            print("  Invalid option.")


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--simulate":
        full_simulation()
    else:
        interactive()
