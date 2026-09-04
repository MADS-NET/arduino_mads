#!/usr/bin/env python3
"""Deepest-call-chain stack usage report.

Used by `make stackreport`. Not a general-purpose tool: reads the .su files
GCC's -fstack-usage writes next to each .o (one line per function: file,
line, col, signature, byte count, qualifier), builds a call graph from the
matching .o files' disassembly (direct calls only -- indirect calls through
function pointers, and recursion, are flagged rather than followed), and
reports the heaviest root-to-leaf stack sum.

Known limitations, acceptable for this purpose (a budgeting aid, not a
correctness proof -- see CURVE_PLAN.md Sec 7.2 for what actually gates the
board):
  - Functions are matched between .su (demangled signature) and objdump
    (mangled symbol, demangled here with c++filt) by signature text. Two
    functions with an identical signature in different translation units
    would collide; none do in this codebase.
  - Calls to symbols with no .su entry (libc, sanitizer runtime, anything
    outside the sources passed in) are treated as leaves contributing 0
    further stack -- this UNDER-counts chains that pass through, e.g.,
    heavy libc code. There is none of that in the crypto/entropy/session
    code paths this matters for.
  - A cycle (mutual recursion, or a recursive function) is broken at the
    point it's detected and the involved function's own frame is still
    counted once; the report says so.
  - Built at -O0 -fno-inline (see Makefile) specifically so this graph
    walk sees real calls instead of inlined bodies -- at -O1+ many of the
    small crypto helpers disappear into their callers and the call graph
    this script builds would be nearly empty.
"""
import re
import subprocess
import sys
from pathlib import Path

CALL_RE = re.compile(r"call(?:q)?\s+[0-9a-f]+\s*<([^+>]+)(?:\+0x[0-9a-f]+)?>")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout


def demangle(sym):
    out = run(["c++filt", sym]).strip()
    return out if out else sym


def parse_su(su_path):
    """Yields (signature, bytes, file, qualifier) for one .su file."""
    text = su_path.read_text(errors="replace")
    for line in text.splitlines():
        if not line.strip():
            continue
        # "file:line:col:signature\tbytes\tqualifier"
        try:
            loc, rest = line.split("\t", 1)
            bytes_str, qualifier = rest.split("\t", 1)
        except ValueError:
            continue
        parts = loc.split(":", 3)
        if len(parts) < 4:
            continue
        file_, _line, _col, sig = parts
        try:
            size = int(bytes_str)
        except ValueError:
            continue
        yield sig.strip(), size, file_, qualifier.strip()


def build_call_graph(obj_path):
    """Returns {caller_symbol: set(callee_symbol)}, mangled names."""
    disasm = run(["objdump", "-d", "--no-show-raw-insn", str(obj_path)])
    graph = {}
    current = None
    label_re = re.compile(r"^[0-9a-f]+ <([^>]+)>:$")
    for line in disasm.splitlines():
        m = label_re.match(line)
        if m:
            current = m.group(1)
            graph.setdefault(current, set())
            continue
        if current is None:
            continue
        m = CALL_RE.search(line)
        if m:
            graph[current].add(m.group(1))
    return graph


def longest_chain(node, stack_of, callees, memo, visiting):
    if node in memo:
        return memo[node]
    if node in visiting:
        # Recursion: count this frame once, no further descent.
        return stack_of.get(node, 0), [node, "(recursion, truncated)"]
    visiting.add(node)
    best_extra = 0
    best_path = []
    for callee in sorted(callees.get(node, ())):
        if callee not in stack_of:
            continue  # leaf: no .su entry (external/libc), see module docstring
        extra, path = longest_chain(callee, stack_of, callees, memo, visiting)
        if extra > best_extra:
            best_extra = extra
            best_path = path
    visiting.discard(node)
    total_extra = best_extra + stack_of.get(node, 0)
    result = (total_extra, [node] + best_path)
    memo[node] = result
    return result


def main():
    if len(sys.argv) != 2:
        print("usage: stackreport.py <build-dir-with-.su-and-.o-files>",
              file=sys.stderr)
        return 2
    build_dir = Path(sys.argv[1])
    su_files = sorted(build_dir.glob("*.su"))
    obj_files = sorted(build_dir.glob("*.o"))

    if not su_files:
        print("stackreport: no .su files found in", build_dir,
              file=sys.stderr)
        return 1

    # signature (demangled) -> bytes
    stack_of = {}
    sig_locations = {}
    for su in su_files:
        for sig, size, file_, qualifier in parse_su(su):
            stack_of[sig] = size
            sig_locations[sig] = f"{file_} [{qualifier}]"

    # mangled-symbol call graph, per object file, merged
    mangled_graph = {}
    for obj in obj_files:
        g = build_call_graph(obj)
        for caller, callees in g.items():
            mangled_graph.setdefault(caller, set()).update(callees)

    # Re-key the graph by demangled signature to match the .su keys.
    demangled_graph = {}
    for caller, callees in mangled_graph.items():
        dcaller = demangle(caller)
        dcallees = {demangle(c) for c in callees}
        demangled_graph.setdefault(dcaller, set()).update(dcallees)

    memo = {}
    results = []
    for sig in stack_of:
        total, path = longest_chain(sig, stack_of, demangled_graph, memo, set())
        results.append((total, sig, path))
    results.sort(reverse=True)

    print(f"stackreport: {len(stack_of)} functions with stack-usage data, "
          f"{len(obj_files)} object files analysed\n")
    print(f"{'bytes':>8}  root")
    for total, sig, path in results[:15]:
        print(f"{total:>8}  {sig}")
    if results:
        total, sig, path = results[0]
        print("\nDeepest chain (root first):")
        for frame in path:
            b = stack_of.get(frame, 0)
            loc = sig_locations.get(frame, "")
            print(f"  {b:>6} B  {frame}  {loc}")
        print(f"\nTOTAL (deepest root-to-leaf sum): {total} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
