import argparse
import math
import collections
import base64
import zlib
import binascii
import sys
import os

def calc_entropy(data):
    """Computes Shannon entropy of the byte data."""
    if not data:
        return 0.0
    counter = collections.Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def analyze_layer(label, data, indent=0):
    pre = "  " * indent
    ent = calc_entropy(data)
    print(f"{pre}[{label}]")
    print(f"{pre}  Length: {len(data)}")
    print(f"{pre}  Unique: {len(set(data))}")
    print(f"{pre}  Entropy: {ent:.4f}")

def main():
    parser = argparse.ArgumentParser(description="Analyze entropy and encoding layers.")
    parser.add_argument("path", nargs="?", help="Input file path")
    parser.add_argument("--string", "-s", help="Input string to analyze")
    parser.add_argument("--window", "-w", type=int, default=256, help="Sliding window size (default: 256)")
    args = parser.parse_args()

    # Acquire input bytes
    raw = b""
    if args.string:
        raw = args.string.encode('utf-8')
    elif args.path:
        if not os.path.exists(args.path):
            print(f"Error: File not found: {args.path}")
            sys.exit(0)
        try:
            with open(args.path, "rb") as f:
                raw = f.read()
        except IOError as e:
            print(f"Error reading file: {e}")
            sys.exit(0)
    else:
        parser.print_help()
        sys.exit(0)

    # 1. Raw Analysis
    analyze_layer("RAW INPUT", raw)

    # 2. Sliding Window Entropy (Summary)
    if len(raw) >= args.window:
        print(f"\n[SLIDING WINDOW] (size={args.window})")
        entropies = []
        # Calculate entropy for each window
        for i in range(len(raw) - args.window + 1):
            chunk = raw[i : i + args.window]
            entropies.append(calc_entropy(chunk))
        
        if entropies:
            print(f"  Min: {min(entropies):.4f}")
            print(f"  Avg: {sum(entropies) / len(entropies):.4f}")
            print(f"  Max: {max(entropies):.4f}")
    
    # 3. Base64 Check
    # Strip whitespace because validate=True is strict
    b64_candidate = raw.strip()
    decoded = None
    try:
        decoded = base64.b64decode(b64_candidate, validate=True)
        print("\n[BASE64 DECODE]")
        print("  Status: SUCCESS")
        analyze_layer("DECODED BYTES", decoded, indent=1)
    except binascii.Error:
        print("\n[BASE64 DECODE]")
        print("  Status: FAILED") # Not valid base64

    # 4. Zlib Check (chained after base64)
    if decoded:
        try:
            decompressed = zlib.decompress(decoded)
            print("\n[ZLIB DECOMPRESS]")
            print("  Status: SUCCESS")
            analyze_layer("DECOMPRESSED", decompressed, indent=1)
        except zlib.error as e:
            # Try raw deflate
            try:
                decompressed = zlib.decompress(decoded, -15)
                print("\n[ZLIB DECOMPRESS (Raw Deflate)]")
                print("  Status: SUCCESS")
                analyze_layer("DECOMPRESSED", decompressed, indent=1)
            except zlib.error:
                print("\n[ZLIB DECOMPRESS]")
                print(f"  Status: FAILED ({e})")

if __name__ == "__main__":
    main()
