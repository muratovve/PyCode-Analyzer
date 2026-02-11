import re
import math
import binascii
from typing import List, Tuple
from ..models import Finding

class StaticDetector:
    def __init__(self):
        # min 20 chars base64-like
        self.b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        self.hex_pattern = re.compile(r'(?:\\x[0-9a-fA-F]{2}){10,}')

    def _calculate_entropy(self, data: bytes) -> float:
        if not data: return 0
        probabilities = [n_x / len(data) for x in set(data) for n_x in [data.count(x)]]
        return -sum([p * math.log(p, 2) for p in probabilities])

    def _get_confidence(self, score: int) -> str:
        if score >= 5: return "HIGH"
        if score >= 3: return "MEDIUM"
        return "LOW"
    
    def _add_finding(self, findings: List[Finding], category: str, technique: str, score: int, location: str, snippet: str = ""):
        findings.append(Finding(
            category=category,
            technique=technique,
            score=score,
            confidence=self._get_confidence(score),
            location=location,
            snippet=snippet
        ))

    def analyze(self, code: str) -> List[Finding]:
        findings = []
        code_bytes = code.encode('utf-8', errors='ignore')
        
        # 1. Whole File Entropy
        file_entropy = self._calculate_entropy(code_bytes)
        if file_entropy > 5.5: 
             self._add_finding(findings, "Static", "High Entropy", 2, "Whole File", f"Entropy: {file_entropy:.2f}")

        # 2. Sliding Window Entropy (locate packed regions)
        # scan in 256-byte chunks, overlap 128
        chunk_size = 256
        step = 128
        if len(code_bytes) > chunk_size:
            max_entropy = 0
            for i in range(0, len(code_bytes) - chunk_size, step):
                chunk = code_bytes[i:i+chunk_size]
                e = self._calculate_entropy(chunk)
                max_entropy = max(max_entropy, e)
                if e > 7.5: # very high entropy in small chunk = packed data
                    self._add_finding(findings, "Static", "Packed Code Block", 3, f"Offset {i}", f"Local Entropy: {e:.2f}")
                    break # report once per file to avoid noise

        # 3. Base64 Blobs (validated)
        for match in self.b64_pattern.finditer(code):
            blob = match.group()
            try:
                decoded = binascii.a2b_base64(blob)
                # check decoded content
                if b'exec' in decoded or b'eval' in decoded or b'import' in decoded:
                     self._add_finding(findings, "String", "Base64 Obfuscated Code", 4, f"Offset {match.start()}", "Contains exec/eval/import")
                elif self._calculate_entropy(decoded) > 5.0:
                     self._add_finding(findings, "String", "High Entropy Base64", 2, f"Offset {match.start()}", "Likely packed data")
                else:
                    # check for zlib header
                    if decoded.startswith(b'\x78\x9c'):
                         self._add_finding(findings, "String", "Base64 -> Zlib", 3, f"Offset {match.start()}", "Zlib header detected")

            except binascii.Error:
                pass # false positive regex match

        # 4. Hex Blobs
        for match in self.hex_pattern.finditer(code):
             self._add_finding(findings, "String", "Hex Blob", 2, f"Offset {match.start()}", match.group()[:50])
            
        return findings
