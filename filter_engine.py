"""
NetGuard — Filter Engine
Provides Wireshark-style display filtering for captured packets.

Supported filter expressions:
  ip.src == 192.168.1.1
  ip.dst == 8.8.8.8
  tcp.port == 443
  udp.port == 53
  protocol == HTTP
  proto == TCP
  ip == 10.0.0.5          (matches src OR dst)
  port == 80              (matches src OR dst port)
  blocked == true
  size > 500
  size < 100

Compound expressions:
  ip.src == 192.168.1.1 && tcp.port == 80
  protocol == TCP || protocol == UDP
  !(ip.src == 10.0.0.1)
"""

import re
import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("NetGuard.Filter")


class FilterSyntaxError(Exception):
    pass


class FilterEngine:
    """
    Parses and evaluates filter expressions against packet dicts.
    Designed for O(1) per-packet evaluation after compilation.
    """

    def __init__(self):
        self.current_expression = ""
        self._compiled = None

    def set_filter(self, expression: str) -> Dict:
        expression = expression.strip()
        if not expression:
            self.clear()
            return {"status": "cleared"}
        try:
            compiled = self._compile(expression)
            self._test_compiled(compiled)
            self._compiled = compiled
            self.current_expression = expression
            return {"status": "ok", "expression": expression}
        except FilterSyntaxError as e:
            return {"status": "error", "error": str(e)}
        except Exception as e:
            return {"status": "error", "error": f"Unexpected error: {e}"}

    def clear(self):
        self.current_expression = ""
        self._compiled = None

    def matches(self, packet: Dict[str, Any]) -> bool:
        if self._compiled is None:
            return True
        try:
            return bool(self._compiled(packet))
        except Exception:
            return True

    def _compile(self, expr: str):
        expr = expr.strip()
        if expr.startswith("(") and expr.endswith(")"):
            inner = expr[1:-1].strip()
            if self._balanced(inner):
                return self._compile(inner)
        if expr.startswith("!") or expr.lower().startswith("not "):
            rest = expr[1:].strip() if expr.startswith("!") else expr[4:].strip()
            inner = self._compile(rest)
            return lambda p, fn=inner: not fn(p)
        or_idx = self._split_logical(expr, ("||", "or"))
        if or_idx is not None:
            left = self._compile(expr[:or_idx[0]])
            right = self._compile(expr[or_idx[1]:])
            return lambda p, l=left, r=right: l(p) or r(p)
        and_idx = self._split_logical(expr, ("&&", "and"))
        if and_idx is not None:
            left = self._compile(expr[:and_idx[0]])
            right = self._compile(expr[and_idx[1]:])
            return lambda p, l=left, r=right: l(p) and r(p)
        return self._compile_condition(expr)

    def _compile_condition(self, expr: str):
        expr = expr.strip()
        pattern = r'^(.+?)\s*(==|!=|>=|<=|>|<|contains)\s*(.+)$'
        m = re.match(pattern, expr, re.IGNORECASE)
        if not m:
            raise FilterSyntaxError(f"Cannot parse condition: {expr!r}")
        field_raw = m.group(1).strip().lower()
        op = m.group(2).strip()
        value_raw = m.group(3).strip().strip('"\'')
        extractor = self._field_extractor(field_raw)
        comparator = self._make_comparator(op, value_raw)
        return lambda p, e=extractor, c=comparator: c(e(p))

    def _field_extractor(self, field: str):
        field_map = {
            "ip.src": lambda p: p.get("src_ip", ""),
            "ip.dst": lambda p: p.get("dst_ip", ""),
            "ip": lambda p: f"{p.get('src_ip','')} {p.get('dst_ip','')}",
            "tcp.port": lambda p: f"{p.get('src_port','')} {p.get('dst_port','')}",
            "udp.port": lambda p: f"{p.get('src_port','')} {p.get('dst_port','')}",
            "port": lambda p: f"{p.get('src_port','')} {p.get('dst_port','')}",
            "src.port": lambda p: str(p.get("src_port", "")),
            "dst.port": lambda p: str(p.get("dst_port", "")),
            "protocol": lambda p: (p.get("protocol") or "").upper(),
            "proto": lambda p: (p.get("protocol") or "").upper(),
            "size": lambda p: p.get("size", 0),
            "length": lambda p: p.get("size", 0),
            "ttl": lambda p: p.get("ttl", 0),
            "blocked": lambda p: str(p.get("blocked", False)).lower(),
            "flags": lambda p: (p.get("flags") or "").upper(),
            "info": lambda p: (p.get("info") or "").lower(),
        }
        if field in field_map:
            return field_map[field]
        raise FilterSyntaxError(f"Unknown field: {field!r}")

    def _make_comparator(self, op: str, value: str):
        def safe_num(v):
            try:
                return float(v)
            except (ValueError, TypeError):
                return None
        num_val = safe_num(value)
        if op == "==":
            if num_val is not None:
                return lambda x, n=num_val: safe_num(x) == n or value.lower() in str(x).lower()
            return lambda x, v=value.lower(): v in str(x).lower()
        if op == "!=":
            if num_val is not None:
                return lambda x, n=num_val: safe_num(x) != n
            return lambda x, v=value.lower(): v not in str(x).lower()
        if op == ">":
            return lambda x, n=num_val: (safe_num(x) or 0) > (n or 0)
        if op == "<":
            return lambda x, n=num_val: (safe_num(x) or 0) < (n or 0)
        if op == ">=":
            return lambda x, n=num_val: (safe_num(x) or 0) >= (n or 0)
        if op == "<=":
            return lambda x, n=num_val: (safe_num(x) or 0) <= (n or 0)
        if op == "contains":
            return lambda x, v=value.lower(): v in str(x).lower()
        raise FilterSyntaxError(f"Unknown operator: {op!r}")

    def _split_logical(self, expr: str, operators: Tuple) -> Optional[Tuple[int, int]]:
        depth = 0
        i = 0
        while i < len(expr):
            c = expr[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif depth == 0:
                for op in operators:
                    if expr[i:i+len(op)].lower() == op.lower():
                        if op.isalpha():
                            before = i == 0 or not expr[i-1].isalpha()
                            after_pos = i + len(op)
                            after = after_pos >= len(expr) or not expr[after_pos].isalpha()
                            if not (before and after):
                                break
                        return (i, i + len(op))
            i += 1
        return None

    def _balanced(self, expr: str) -> bool:
        depth = 0
        for c in expr:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            if depth < 0:
                return False
        return depth == 0

    def _test_compiled(self, fn):
        test_pkt = {
            "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
            "src_port": 12345, "dst_port": 80,
            "protocol": "TCP", "size": 100, "ttl": 64,
            "flags": "SYN", "blocked": False, "info": "test"
        }
        fn(test_pkt)
