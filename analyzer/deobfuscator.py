import base64
import binascii
import zlib
import bz2
import re
import ast

class SafeDeobfuscator:
    def __init__(self):
        # Limit preview size
        self.max_preview_len = 1000

    def _safe_decode_bytes(self, data: bytes) -> str:
        """Try to decode bytes to utf-8 or latin-1 if it looks like text."""
        try:
            text = data.decode('utf-8')
            if text.isprintable():
                return text
        except UnicodeDecodeError:
            pass
        
        try:
            # Latin-1 is lax, so we add a check for control chars to avoid binary garbage
            text = data.decode('latin-1')
            # Check if it has too many non-printable chars (excluding whitespace)
            printable_ratio = sum(c.isprintable() or c.isspace() for c in text) / len(text) if text else 0
            if printable_ratio > 0.9:
                 return text
        except Exception:
            pass
        return f"<Binary Data: {len(data)} bytes>"

    def try_deobfuscate(self, text: str) -> str:
        """Attempt multiple layers of decoding on the input string."""
        preview = ""
        
        # Base64
        # We search for the largest suspicious b64-like blob to decode
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        matches = b64_pattern.findall(text)
        if matches:
            # Take the longest match
            blob = max(matches, key=len)
            try:
                decoded = base64.b64decode(blob)
                
                # Check for zlib/bz2 inside the decoded data
                try:
                    decoded = zlib.decompress(decoded)
                    preview += " [Base64 -> Zlib] "
                except zlib.error:
                    try:
                        decoded = bz2.decompress(decoded)
                        preview += " [Base64 -> Bz2] "
                    except Exception:
                        preview += " [Base64] "
                
                preview += self._safe_decode_bytes(decoded)
                return preview[:self.max_preview_len]
            except Exception:
                pass

        # Hex (\xNN)
        # Find long hex strings
        hex_pattern = re.compile(r'(?:\\x[0-9a-fA-F]{2}){10,}')
        hex_matches = hex_pattern.findall(text)
        if hex_matches:
            blob = max(hex_matches, key=len)
            # clean \x
            clean_hex = blob.replace('\\x', '')
            try:
                decoded = binascii.unhexlify(clean_hex)
                preview += " [Hex] " + self._safe_decode_bytes(decoded)
                return preview[:self.max_preview_len]
            except Exception:
                pass

        try:
            tree = ast.parse(text)
            char_accum = []

            
            chr_matches = list(re.finditer(r'chr\((\d+)\)', text))
            if len(chr_matches) > 5:
                # reconstruct
                chars = []
                for m in chr_matches:
                    try:
                        val = int(m.group(1))
                        chars.append(chr(val))
                    except ValueError:
                        pass
                if chars:
                    preview += " [Chr Assembly] " + "".join(chars)
                    return preview[:self.max_preview_len]

        except Exception:
            pass

        return ""

