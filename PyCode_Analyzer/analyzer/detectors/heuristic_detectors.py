import ast
from typing import List, Dict, Set, Optional
from ..models import Finding

class HeuristicDetector(ast.NodeVisitor):
    def __init__(self):
        self.findings: List[Finding] = []
        # var_name -> source_type (e.g. "input", "base64", "zlib")
        self.tainted_vars: Dict[str, str] = {} 
        self.single_char_vars = 0
        self.total_vars = 0

    def _get_confidence(self, score: int) -> str:
        if score >= 5: return "HIGH"
        if score >= 3: return "MEDIUM"
        return "LOW"

    def _add_finding(self, category: str, technique: str, score: int, node: ast.AST, snippet: str = ""):
        self.findings.append(Finding(
            category=category,
            technique=technique,
            score=score,
            confidence=self._get_confidence(score),
            location=f"Line {getattr(node, 'lineno', '?')}",
            snippet=snippet
        ))

    def visit_Assign(self, node: ast.Assign):
        # track variable assignments for taint/pipeline analysis
        # source = value
        if not node.targets: return
        target = node.targets[0]
        if not isinstance(target, ast.Name): return
        
        var_name = target.id
        self.total_vars += 1
        if len(var_name) == 1: self.single_char_vars += 1

        # check what is being assigned
        source_type = self._classify_source(node.value)
        if source_type:
            self.tainted_vars[var_name] = source_type

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_func_name(node.func)
        
        # 1. Pipeline Sinks (exec/eval)
        if func_name in {'exec', 'eval', 'compile'}:
            # check arguments for tainted vars
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                    source = self.tainted_vars[arg.id]
                    self._add_finding("Flow", f"Tainted execution from {source}", 5, node, f"{func_name}({arg.id})")
        
        # 2. chr() loops construction
        if func_name == 'chr':
             self._add_finding("Obfuscation", "chr() character assembly", 1, node, "chr(...)")

        # 3. ''.join()
        if func_name == 'join' and isinstance(node.func, ast.Attribute):
             if isinstance(node.func.value, ast.Constant) and node.func.value.value == '':
                  self._add_finding("Obfuscation", "String join construction", 1, node, "''.join(...)")

        self.generic_visit(node)

    def _classify_source(self, node: ast.AST) -> Optional[str]:
        # Identify taint sources and pipeline stages
        if isinstance(node, ast.Call):
            name = self._get_func_name(node.func)
            
            # Taint Sources
            if name in {'input', 'sys.stdin.read'}: return "User Input"
            if 'socket' in name and 'recv' in name: return "Network Input"
            if 'open' in name: return "File Read"
            
            # Pipeline Stages
            if 'b64decode' in name: return "Base64 Decode"
            if 'decompress' in name: return "Zlib/Bz2 Decompress"
            if 'loads' in name and 'marshal' in name: return "Marshal Load"
            
            if len(node.args) > 0 and isinstance(node.args[0], ast.Name):
                if node.args[0].id in self.tainted_vars:
                    prev_taint = self.tainted_vars[node.args[0].id]
                    return f"{prev_taint} -> {name}"
                    
        return None

    def _get_func_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._get_func_name(node.value)}.{node.attr}"
        return "unknown"

    def analyze(self, code: str) -> List[Finding]:
        self.findings = []
        self.tainted_vars = {}
        self.single_char_vars = 0
        self.total_vars = 0
        
        try:
            tree = ast.parse(code)
            self.visit(tree)
            
            # Global stats analysis
            if self.total_vars > 10:
                ratio = self.single_char_vars / self.total_vars
                if ratio > 0.5:
                    self.findings.append(Finding(
                        category="Heuristic",
                        technique="High Single-Char Var Density",
                        score=2,
                        confidence="LOW",
                        location="Global",
                        description=f"{ratio:.1%} variables are single-char"
                    ))
                    
        except SyntaxError:
            pass 
            
        return self.findings
