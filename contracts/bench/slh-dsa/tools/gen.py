#!/usr/bin/env python3
"""Renders the two verifiers in src/ from tools/SlhDsaSha2Verifier.sol.in.

    python3 tools/gen.py           # write src/*.sol
    python3 tools/gen.py --check   # fail if src/ differs from what the template gives

The parameter sets and every derived number (len1, len2, len, m, the signature size, the digest's split) come from
fips205.Params, which computes them with FIPS 205's formulas and checks m against the published value.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fips205 as f  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src")

SETS = [
    (f.SHA2_128S, "SlhDsaSha2_128s", "SLH-DSA-SHA2-128s verifier (FIPS 205)", ""),
    (f.SHA2_128_24_DRAFT, "SlhDsaSha2_128_24_DRAFT",
     "SLH-DSA-SHA2-128-24 verifier: a DRAFT parameter set (NIST SP 800-230 ipd)",
     "///         DRAFT: SLH-DSA-SHA2-128-24 is from the initial public draft of NIST SP 800-230 and may change. Its\n"
     "///         known answers come from this benchmark's own Python reference only (fixtures/draft-sha2-128-24.json).\n"),
]


def constants(p):
    assert p.m <= 32, "one MGF1 block"
    assert p.k * p.a <= 256 and 8 * p.m <= 256, "the digest fits a word"
    csum_bytes = -(-p.len2 * p.lgw // 8)
    csum_shift = (8 - ((p.len2 * p.lgw) % 8)) % 8
    tree_bits = p.h - p.hp
    rows = [
        ("SIG_BYTES", p.sig_bytes, "signature: R | SIG_FORS | SIG_HT"),
        ("K", p.k, "FORS trees"),
        ("A", p.a, "FORS tree height"),
        ("A_MASK", (1 << p.a) - 1, "2^a - 1"),
        ("D", p.d, "hypertree layers"),
        ("HP", p.hp, "h' = h / d, XMSS tree height"),
        ("HP_MASK", (1 << p.hp) - 1, "2^h' - 1"),
        ("LGW", p.lgw, "lg w"),
        ("W1", p.w - 1, "w - 1"),
        ("LEN1", p.len1, "len1 = 8n / lg w"),
        ("LEN", p.len, f"len = len1 + len2, len2 = {p.len2}"),
        ("W2", p.w - 2, "w - 2"),
        ("MSG_SHIFT", 256 - p.lgw, "message digit i is msg >> (MSG_SHIFT - lg w i), msg left-aligned"),
        ("CSUM_SHIFT", 8 * csum_bytes - p.lgw - csum_shift + p.lgw * p.len1,
         f"checksum digit i is csum >> (CSUM_SHIFT - lg w i): csum << {csum_shift} in {csum_bytes} byte(s)"),
        ("TREE_SHIFT", 256 - 8 * (p.md_bytes + p.tree_bytes),
         f"idx_tree: digest bytes {p.md_bytes} .. {p.md_bytes + p.tree_bytes - 1}" if p.tree_bytes
         else "idx_tree: none (d = 1), always 0"),
        ("TREE_MASK", (1 << tree_bits) - 1, f"mod 2^(h - h') = 2^{tree_bits}"),
        ("LEAF_SHIFT", 256 - 8 * (p.md_bytes + p.tree_bytes + p.leaf_bytes),
         f"idx_leaf: digest bytes {p.md_bytes + p.tree_bytes} .. {p.m - 1}"),
        ("FORS_TREE_BYTES", (p.a + 1) * p.n, "one FORS tree's signature: (a + 1) n"),
        ("HT_OFFSET", p.n + p.k * (p.a + 1) * p.n, "SIG_HT's offset: n + k (a + 1) n"),
        ("XMSS_BYTES", (p.len + p.hp) * p.n, "one XMSS signature: (len + h') n"),
        ("T_K_BYTES", 64 + 22 + p.k * p.n, "T_k's input: 64 + 22 + k n"),
        ("T_LEN_BYTES", 64 + 22 + p.len * p.n, "T_len's input: 64 + 22 + len n"),
    ]
    code = [f"    uint256 private constant {name} = {f'0x{v:x}' if v > 1 << 32 else v};" for name, v, _ in rows]
    width = max(len(c) for c in code)
    return "".join(f"{c.ljust(width)} // {note}\n" for c, (_, _, note) in zip(code, rows))


def node(indent, adrs, bit, ptr):
    """One H step: the running node sits in the left (bit 0) or right (bit 1) half of M2 at 0x56. Write the address
    and the authentication node at calldata `ptr` into the rest: for bit 0, all of ADRSc (a word ending at 0x56) and
    the right half (spilling 16 bytes past the input); for bit 1, ADRSc's last 16 bytes and the left half in one word
    at 0x46, leaving ADRSc's first 6 bytes (layer, tree) as they are."""
    lines = [
        f"switch {bit}",
        "case 0 {",
        f"    mstore(0x36, {adrs})",
        f"    mstore(0x66, calldataload({ptr}))",
        "}",
        f"default {{ mstore(0x46, or(shl(128, {adrs}), shr(128, calldataload({ptr})))) }}",
    ]
    return "\n".join(indent + l for l in lines)


def chain(indent, p):
    """chain(sig_i, a, w - 1 - a) of Algorithm 8, straight-line: the w - 2 - a steps before the last one in blocks of
    8, 4, 2 and 1 (the bits of their count), then the last one into T_len's input."""
    end = "add(add(T_BUF, 0x56), shl(4, i))"
    lines = [
        "switch eq(a, W1)",
        f"case 1 {{ calldatacopy({end}, sigp, 16) }} // a chain of length 0",
        "default {",
        "    // F's input: ADRSc's tail (chain i, hash a) | sig_i",
        "    mstore(0x46, or(shl(128, or(wots, or(shl(32, i), a))), shr(128, calldataload(sigp))))",
        "    let r := sub(W2, a)",
    ]
    bit = 1 << ((p.w - 2).bit_length() - 1)
    while bit:
        lines.append(f"    if and(r, {bit}) {{")
        for k in range(1, bit + 1):
            lines.append("        pop(staticcall(gas(), 2, 0, 102, 0x56, 0x20))")
            lines.append(f"        mstore8(0x55, add(a, {k})) // the next hash address")
        lines.append(f"        a := add(a, {bit})")
        lines.append("    }")
        bit >>= 1
    lines += [
        f"    pop(staticcall(gas(), 2, 0, 102, {end}, 0x20))",
        "}",
        "sigp := add(sigp, 16)",
    ]
    return "\n".join(indent + l for l in lines)


def levels(indent, z, adrs_base, index, bit_src, ptr, first_auth, last_dst):
    """Heights 1 .. z of an authentication path, unrolled. The node at height k - 1 sits in the half of M2 given by
    bit k - 1 of `bit_src`; height k's address is adrs_base | k << 32 | index >> k; the auth node is at calldata
    ptr + first_auth + 16 (k - 1). The last H writes to last_dst, the others where the next H wants their output."""
    out = []
    for k in range(1, z + 1):
        bit = f"and(shr({k - 1}, {bit_src}), 1)" if k > 1 else f"and({bit_src}, 1)"
        if k == z:
            bit = f"shr({k - 1}, {bit_src})"  # bit_src < 2^z
        adrs = f"or({adrs_base}, or(0x{k << 32:x}, shr({k}, {index})))"
        auth = f"add({ptr}, {first_auth + 16 * (k - 1)})"
        out.append(f"// height {k}")
        out.append(node("", adrs, bit, auth))
        dst = last_dst if k == z else f"add(0x56, shl(4, and(shr({k}, {bit_src}), 1)))"
        out.append(f"pop(staticcall(gas(), 2, 0, 118, {dst}, 0x20))")
    return "\n".join(indent + l for block in out for l in block.split("\n"))


def render(p, contract, title, draft):
    t = open(os.path.join(HERE, "SlhDsaSha2Verifier.sol.in")).read()
    end = 0x100 + 0x56 + 16 * max(p.len, p.k) + 16
    msg = (end + 0x3f) // 0x20 * 0x20
    line = f"n={p.n} h={p.h} d={p.d} h'={p.hp} a={p.a} k={p.k} lg w={p.lgw} m={p.m}"
    for key, value in [("@@TITLE@@", title), ("@@CONTRACT@@", contract), ("@@DRAFT_NOTICE@@", draft),
                       ("@@PARAMS_LINE@@", line), ("@@PK_BYTES@@", str(p.pk_bytes)),
                       ("@@SIG_BYTES@@", f"{p.sig_bytes:,}"), ("@@CONSTANTS@@", constants(p)),
                       ("@@MSG@@", f"0x{msg:x}")]:
        t = t.replace(key, value)
    t = re.sub(r"(?m)^( *)@@NODE:([^:]+):([^:]+):([^:]+)@@$", lambda m: node(*m.groups()), t)
    t = re.sub(r"(?m)^( *)@@CHAIN@@$", lambda m: chain(m.group(1), p), t)
    t = re.sub(r"(?m)^( *)@@FORS_LEVELS@@$", lambda m: levels(m.group(1), p.a, "base", "leaf", "idx", "p", 16,
                                                              "add(add(T_BUF, 0x56), shl(4, i))"), t)
    t = re.sub(r"(?m)^( *)@@XMSS_LEVELS@@$", lambda m: levels(m.group(1), p.hp, "tree", "idxLeaf", "idxLeaf", "sigp",
                                                              0, "OUT"), t)
    assert "@@" not in t
    return t


if __name__ == "__main__":
    stale = []
    for p, contract, title, draft in SETS:
        path = os.path.join(SRC, contract + ".sol")
        text = render(p, contract, title, draft)
        if "--check" in sys.argv:
            if not os.path.exists(path) or open(path).read() != text:
                stale.append(path)
        else:
            open(path, "w").write(text)
    if stale:
        sys.exit("stale, run tools/gen.py: " + ", ".join(stale))
