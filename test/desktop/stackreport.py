#!/usr/bin/env python3
"""Deepest-call-chain stack usage report.

Used by `make stackreport`. Not a general-purpose tool: reads the .su files
GCC's -fstack-usage writes next to each .o (one line per function: file,
line, col, signature, byte count, qualifier), builds a call graph from the
matching .o files' disassembly (direct calls only -- indirect calls through
function pointers, and recursion, are flagged rather than followed), and
reports the heaviest root-to-leaf stack sum.

Known limitations, acceptable for this purpose (a budgeting aid, not a
correctness proof -- see DEVELOPER.md, Stack for what actually gates the
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
    this script builds would be nearly empty. `make stackreport-arm` is the
    deliberate exception: it builds at the board's real -Os, where an
    inlined callee's frame is folded into its caller's .su number, so the
    chain sums stay meaningful even though the graph is much flatter. That
    is the configuration to believe for a board budget; the -O0 one is for
    seeing structure.
  - Both C++ and C sources are included. Leaving C out was a real
    under-count: Monocypher is C, and it holds the deepest frame in the
    whole handshake (see DEVELOPER.md).
"""
import os
import re
import subprocess
import sys
from pathlib import Path

# Both toolchains this is used with. x86-64: `call`/`callq`. ARM (Thumb):
# `bl`/`blx` for calls, and `b`/`b.n`/`b.w` for tail calls, which at -Os are
# real edges in the call graph and must be followed. A plain `b` is also how
# GCC writes an ordinary branch *within* a function, which objdump renders as
# <same_symbol+0x..>; those self-edges are dropped in build_call_graph()
# rather than being mistaken for recursion.
CALL_RE = re.compile(
    r"(?:^|\s)(?:callq?|blx?|b\.[nw])\s+[0-9a-f]+\s*<([^+>]+)(?:\+0x[0-9a-f]+)?>"
)

# In an *unlinked* object, a call to a function in another section is not
# resolved yet: objdump renders it as `bl 0 <containing_symbol>` -- a
# placeholder pointing at offset 0 of the current section, i.e. the calling
# function itself. Under -ffunction-sections (which the Arduino core uses)
# that is every cross-function call, so reading the disassembly alone yields
# a graph of nothing but self-edges. The real callee is in the accompanying
# relocation, which is why this reads `objdump -dr` and prefers the
# relocation symbol. Only call/branch relocation types are followed; data
# relocations are not edges.
RELOC_RE = re.compile(
    r"R_(?:ARM|AARCH64|X86_64|386)_\S*?(THM_CALL|THM_JUMP24|JUMP24|CALL|PLT32|PC24)\b"
    r"\s+(\S+)"
)

# The same problem in Mach-O dress, which is what a macOS host build
# produces: branch targets disassemble as <ltmp0+0x38> (the section, not the
# callee) and the real name is again only in the relocation. Mach-O also
# prefixes every symbol with an underscore, so "_crypto_x25519" and
# "__ZN4Mads..." need one stripped before they match a .su entry or demangle.
MACHO_RELOC_RE = re.compile(r"(?:ARM64|X86_64|ARM)_RELOC_\S*BRANCH\S*\s+(\S+)")

# Override for cross builds, e.g.
#   OBJDUMP=arm-none-eabi-objdump CXXFILT=arm-none-eabi-c++filt
OBJDUMP = os.environ.get("OBJDUMP", "objdump")
CXXFILT = os.environ.get("CXXFILT", "c++filt")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout


def demangle(sym):
    out = run([CXXFILT, sym]).strip()
    return out if out else sym


def func_key(text):
    """Reduce a .su signature or a demangled symbol to a comparable key.

    The two sides disagree on spelling for the same function: -fstack-usage
    writes the *source* signature ("bool Mads::box_beforenm(uint8_t*, const
    uint8_t*, ...)"), while c++filt writes its own canonical rendering with
    no return type and typedefs expanded ("Mads::box_beforenm(unsigned
    char*, unsigned char const*, ...)"). Matching those verbatim never
    succeeds, so before this normalisation *every* C++ function looked like
    a leaf and only the C (Monocypher) chains resolved -- a silent and
    badly misleading under-count. Reducing both to the qualified name
    ("Mads::box_beforenm") makes them meet.

    Overloads collapse onto one key; the caller keeps the largest frame, so
    a chain through an overload set is over- rather than under-stated.
    """
    text = text.strip()
    # The two spellings of an anonymous namespace, before any paren scan --
    # "(anonymous namespace)" contains both a paren and a space.
    text = text.replace("(anonymous namespace)", "{anonymous}")
    # Cut the parameter list at the first top-level "(".
    depth = 0
    cut = len(text)
    for i, ch in enumerate(text):
        if ch in "<[":
            depth += 1
        elif ch in ">]":
            depth -= 1
        elif ch == "(" and depth == 0:
            cut = i
            break
    head = text[:cut].strip()
    # Drop a leading return type, which .su has and c++filt does not.
    return head.split()[-1] if head.split() else head


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
        # Two dialects. GCC: "file:line:col:signature". Clang (which is what
        # `g++` is on macOS): "file:line:mangled_symbol" -- no column, and
        # the symbol is mangled rather than a source signature. Requiring
        # GCC's four fields silently discarded every function on a clang
        # host, which read as "0 functions with stack-usage data".
        parts = loc.split(":", 3)
        if len(parts) == 4:
            file_, _line, _col, sig = parts
        elif len(parts) == 3:
            file_, _line, sig = parts
        else:
            continue
        try:
            size = int(bytes_str)
        except ValueError:
            continue
        yield sig.strip(), size, file_, qualifier.strip()


def build_call_graph(obj_path):
    """Returns {caller_symbol: set(callee_symbol)}, mangled names."""
    disasm = run([OBJDUMP, "-dr", "--no-show-raw-insn", str(obj_path)])
    is_macho = "_RELOC_" in disasm

    def norm(sym):
        # Mach-O's leading underscore, see MACHO_RELOC_RE.
        return sym[1:] if is_macho and sym.startswith("_") else sym

    graph = {}
    current = None
    label_re = re.compile(r"^[0-9a-f]+ <([^>]+)>:$")
    for line in disasm.splitlines():
        m = label_re.match(line)
        if m:
            current = norm(m.group(1))
            graph.setdefault(current, set())
            continue
        if current is None:
            continue
        m = RELOC_RE.search(line) or MACHO_RELOC_RE.search(line)
        if m:
            # Relocation lines carry the true callee; see RELOC_RE above.
            # Strip any "+0x4" addend off the symbol name.
            callee = norm(m.group(m.lastindex).split("+")[0])
            if callee != current:
                graph[current].add(callee)
            continue
        m = CALL_RE.search(line)
        if m and m.group(1) != current:
            # != current drops intra-function branches (see CALL_RE above).
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
    if not 2 <= len(sys.argv) <= 3:
        print("usage: stackreport.py <build-dir-with-.su-and-.o-files> "
              "[root-substring]",
              file=sys.stderr)
        print("  root-substring: report the chain for every function whose "
              "name contains it,\n"
              "                  instead of only the single deepest one. Use "
              "this to budget one\n"
              "                  entry point (e.g. crypto_x25519, "
              "curve_handshake) rather than\n"
              "                  whatever happens to be heaviest overall.",
              file=sys.stderr)
        return 2
    build_dir = Path(sys.argv[1])
    root_filter = sys.argv[2] if len(sys.argv) == 3 else None
    su_files = sorted(build_dir.glob("*.su"))
    obj_files = sorted(build_dir.glob("*.o"))

    if not su_files:
        print("stackreport: no .su files found in", build_dir,
              file=sys.stderr)
        return 1

    # signature (demangled) -> bytes
    stack_of = {}
    sig_locations = {}
    display = {}
    for su in su_files:
        for sig, size, file_, qualifier in parse_su(su):
            # Clang's .su carries a mangled symbol; GCC's a source signature.
            if sig.startswith("_Z"):
                sig = demangle(sig)
            key = func_key(sig)
            # Overloads share a key: keep the largest frame (see func_key).
            if size >= stack_of.get(key, -1):
                stack_of[key] = size
                sig_locations[key] = f"{file_} [{qualifier}]"
                display[key] = sig

    # mangled-symbol call graph, per object file, merged
    mangled_graph = {}
    for obj in obj_files:
        g = build_call_graph(obj)
        for caller, callees in g.items():
            mangled_graph.setdefault(caller, set()).update(callees)

    # Re-key the graph by demangled signature to match the .su keys.
    demangled_graph = {}
    for caller, callees in mangled_graph.items():
        dcaller = func_key(demangle(caller))
        dcallees = {func_key(demangle(c)) for c in callees}
        dcallees.discard(dcaller)
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
        print(f"{total:>8}  {display.get(sig, sig)}")
    if root_filter:
        matches = [r for r in results
                   if root_filter in r[1] or root_filter in display.get(r[1], "")]
        if not matches:
            print(f"\nNo function matching {root_filter!r}.")
            return 1
        for total, sig, path in matches:
            print(f"\nChain for {sig} (root first):")
            for frame in path:
                b = stack_of.get(frame, 0)
                loc = sig_locations.get(frame, "")
                print(f"  {b:>6} B  {display.get(frame, frame)}  {loc}")
            print(f"  TOTAL: {total} bytes")
        return 0

    if results:
        total, sig, path = results[0]
        print("\nDeepest chain (root first):")
        for frame in path:
            b = stack_of.get(frame, 0)
            loc = sig_locations.get(frame, "")
            print(f"  {b:>6} B  {display.get(frame, frame)}  {loc}")
        print(f"\nTOTAL (deepest root-to-leaf sum): {total} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
