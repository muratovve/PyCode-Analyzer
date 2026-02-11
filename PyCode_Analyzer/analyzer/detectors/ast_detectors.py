import ast
from typing import List, Dict, Set, Any
from ..models import Finding

class ASTDetector(ast.NodeVisitor):
    def __init__(self):
        self.findings: List[Finding] = []
        self.imports: Dict[str, str] = {}  # alias -> real_name
        self.function_defs: Dict[str, List[str]] = {} # func_name -> [called_funcs]
        self.current_func: str = "global"
        self.call_graph: Dict[str, List[str]] = {} # caller -> [callees]
        
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

    def visit_Import(self, node: ast.Import):
        # track imports to resolve aliases later
        for alias in node.names:
            real_name = alias.name
            as_name = alias.asname or alias.name
            self.imports[as_name] = real_name
            
            # suspicious imports
            if real_name in {'marshal', 'subprocess', 'os', 'sys', 'platform'}:
                self._add_finding("Import", f"Suspicious import: {real_name}", 1, node, f"import {real_name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            real_name = f"{module}.{alias.name}" if module else alias.name
            as_name = alias.asname or alias.name
            self.imports[as_name] = real_name
            
            if module in {'marshal', 'subprocess', 'os', 'sys'} or alias.name == 'system':
                self._add_finding("Import", f"Suspicious import: {real_name}", 1, node, f"from {module} import {alias.name}")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # track current scope for call graph
        prev_func = self.current_func
        self.current_func = node.name
        self.call_graph[node.name] = []
        
        self.generic_visit(node)
        
        self.current_func = prev_func

    def visit_Call(self, node: ast.Call):
        # resolve function name handling aliases (e.g. b64decode) and attributes (e.g. os.system)
        func_name = self._resolve_name(node.func)
        
        # update call graph
        if self.current_func in self.call_graph:
            self.call_graph[self.current_func].append(func_name)
            
        # 1. direct exec/eval/compile
        if func_name in {'exec', 'eval', 'compile'}:
            self._add_finding("Execution", f"Direct {func_name} call", 3, node, f"{func_name}(...)")

        # 2. system commands
        if func_name in {'os.system', 'os.popen', 'subprocess.call', 'subprocess.run', 'subprocess.Popen'}:
             self._add_finding("Execution", "Shell command execution", 2, node, func_name)
             
        # 3. dynamic execution via getattr
        if func_name == 'getattr':
             self._add_finding("Dynamic", "getattr usage (possible detection bypass)", 2, node, "getattr(...)")
             
        # 4. __import__ usage
        if func_name == '__import__':
            self._add_finding("Dynamic", "__import__ dynamic loading", 2, node, "__import__(...)")

        self.generic_visit(node)

    def _resolve_name(self, node: ast.AST) -> str:
        # handle simple names: 'exec'
        if isinstance(node, ast.Name):
            return self.imports.get(node.id, node.id)
            
        # handle attributes: 'os.system'
        if isinstance(node, ast.Attribute):
            value_name = self._resolve_name(node.value)
            return f"{value_name}.{node.attr}"
            
        return "unknown"

    def analyze(self, code: str) -> List[Finding]:
        self.findings = []
        self.imports = {}
        self.call_graph = {}
        
        try:
            tree = ast.parse(code)
            self.visit(tree)
            
            # Post-analysis: Check specifically for indirect execution patterns in graph
            # e.g. defined function calling exec
            for caller, callees in self.call_graph.items():
                if any(c in {'exec', 'eval'} for c in callees):
                    # find definition node... simplified here just to add finding
                    # would need to store nodes in map to be precise with line number
                    pass 

        except SyntaxError as e:
            self.findings.append(Finding(
                category="AST",
                technique="Syntax Error",
                score=0,
                confidence="HIGH",
                location=f"Line {e.lineno}",
                description="Code parsing failed"
            ))
            
        return self.findings
