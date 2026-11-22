#!/usr/bin/env python3
"""Independent verifier for mmMover "Offload Proof" -- Python standard library only (3.8+).

    python verify_proof.py <file | card folder> [--offline]
    python verify_proof.py --make-vectors <out.json>

What it checks (written from the format specification, not from mmMover's program):

  1. the SHA-256 and size of the file are listed in a `_REPORT/offload_proof*.json` manifest of its card folder;
  2. that manifest is canonical JSON (RFC 8785), its Merkle root (RFC 6962, SHA-256) and file count are right;
  3. `<manifest>.ots` is an OpenTimestamps proof of exactly the manifest's bytes (SHA-256 of them = its digest);
  4. a Bitcoin attestation in it matches the block header (merkle root = bytes 36-68, time = bytes 68-72) given by
     two independent block explorers, each header hashing to its block hash and carrying its proof of work.

It says only that the file existed unchanged no later than the time of the Bitcoin block -- never that it is
authentic. Exit code: 0 OK, 1 FAILED, 2 NOT YET (only pending / offline / explorers unreachable / no .ots yet).
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys
import unicodedata
import urllib.request
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

EXIT_OK, EXIT_FAILED, EXIT_NOT_YET = 0, 1, 2

HEADER_SOURCES = ["https://blockstream.info/api", "https://mempool.space/api"]
POW_LIMIT = (1 << 224) - 1  # Bitcoin's proof-of-work limit: no block's target was ever easier
CLOCK_TOLERANCE_SECONDS = 48 * 3600
MAX_FILE_BYTES = 256 * 1024 * 1024  # a manifest of a million files is ~300 MB; larger is not ours
MAX_OTS_BYTES = 4 * 1024 * 1024  # a real .ots is a few kB (the same cap as mmMover's)
MAX_HTTP_BYTES = 64 * 1024
MAX_INT = 9007199254740991  # 2^53 - 1: RFC 8785 numbers are IEEE doubles; the manifest has only small integers
MAX_HEIGHTS = 16  # Bitcoin heights looked up per .ots (a hostile one could list thousands)

# ---------------------------------------------------------------------------------------------------------------
# RIPEMD-160: hashlib has it only when OpenSSL does (OpenSSL 3 often hides it), so there is a pure-Python one.
# ---------------------------------------------------------------------------------------------------------------

_R1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
       7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
       3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
       1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
       4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
_R2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
       6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
       15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
       8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
       12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
_S1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
       7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
       11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
       11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
       9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
_S2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
       9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
       9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
       15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
       8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
_K1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_K2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
_M32 = 0xFFFFFFFF


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32


def _f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & _M32 & z)
    if j < 48:
        return (x | (~y & _M32)) ^ z
    if j < 64:
        return (x & z) | (y & ~z & _M32)
    return x ^ (y | (~z & _M32))


def ripemd160_pure(data):
    """RIPEMD-160 of `data` (bytes) in pure Python."""
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytes(data) + b"\x80"
    msg += b"\x00" * ((56 - len(msg)) % 64) + struct.pack("<Q", (len(data) * 8) & 0xFFFFFFFFFFFFFFFF)
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off:off + 64])
        a1, b1, c1, d1, e1 = h
        a2, b2, c2, d2, e2 = h
        for j in range(80):
            t = (_rol((a1 + _f(j, b1, c1, d1) + x[_R1[j]] + _K1[j // 16]) & _M32, _S1[j]) + e1) & _M32
            a1, e1, d1, c1, b1 = e1, d1, _rol(c1, 10), b1, t
            t = (_rol((a2 + _f(79 - j, b2, c2, d2) + x[_R2[j]] + _K2[j // 16]) & _M32, _S2[j]) + e2) & _M32
            a2, e2, d2, c2, b2 = e2, d2, _rol(c2, 10), b2, t
        t = (h[1] + c1 + d2) & _M32
        h[1] = (h[2] + d1 + e2) & _M32
        h[2] = (h[3] + e1 + a2) & _M32
        h[3] = (h[4] + a1 + b2) & _M32
        h[4] = (h[0] + b1 + c2) & _M32
        h[0] = t
    return struct.pack("<5I", *h)


def ripemd160(data):
    """hashlib's RIPEMD-160 when this Python's OpenSSL has it, else the pure-Python one."""
    try:
        return hashlib.new("ripemd160", data).digest()
    except (ValueError, TypeError):
        return ripemd160_pure(data)


def sha256(data):
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------------------------------------------
# Canonical JSON (RFC 8785) for the manifest's subset: strings, integers, booleans, null, arrays, objects.
# ---------------------------------------------------------------------------------------------------------------

_ESCAPES = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x0C: "\\f", 0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t"}


def jcs_string(s):
    """A JSON string as RFC 8785 writes it: only `\\" \\\\ \\b \\f \\n \\r \\t`, other U+0000-U+001F as `\\u00xx` and
    a lone surrogate as `\\udxxx`, all lower-case; everything else (also U+007F, U+2028, emoji) literally."""
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c in _ESCAPES:
            out.append(_ESCAPES[c])
        elif c < 0x20 or 0xD800 <= c <= 0xDFFF:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value):
    """The canonical text of a parsed JSON value (keys sorted by UTF-16 code units, no spaces).
    Floats and integers beyond 2^53-1 are refused (the manifest has none)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise ValueError("integer out of the range RFC 8785 numbers can hold exactly")
        return str(value)
    if isinstance(value, str):
        return jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(jcs_string(k) + ":" + jcs(value[k]) for k in keys) + "}"
    raise ValueError("not a JSON value: %r" % (value,))


def jcs_bytes(value):
    return jcs(value).encode("utf-8")


def _no_float(text):
    raise ValueError("a non-integer number")


def _no_constant(text):
    raise ValueError("not a JSON number: " + text)


def _no_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key " + jcs_string(k))
        d[k] = v
    return d


def parse_json(text):
    return json.loads(text, parse_float=_no_float, parse_constant=_no_constant, object_pairs_hook=_no_duplicates)


# ---------------------------------------------------------------------------------------------------------------
# Merkle tree (RFC 6962 section 2.1) over the manifest's files.
# ---------------------------------------------------------------------------------------------------------------

def leaf_data(sha256_bytes, size):
    """32 bytes of the file's SHA-256, then its size as 8 bytes big-endian."""
    if len(sha256_bytes) != 32:
        raise ValueError("a SHA-256 is 32 bytes")
    return sha256_bytes + struct.pack(">Q", size)


def ordered_leaves(files):
    """`files` = (sha256 bytes, size) pairs -> leaf data, sorted by SHA-256 (bytewise), then size; duplicates stay."""
    return [leaf_data(s, n) for s, n in sorted(files)]


def merkle_root(leaf_datas):
    """MTH of RFC 6962; the empty tree is SHA-256 of the empty string."""
    n = len(leaf_datas)
    if n == 0:
        return sha256(b"")
    level = [sha256(b"\x00" + d) for d in leaf_datas]
    # RFC 6962 splits at the largest power of two below n; combining adjacent pairs level by level and carrying an
    # odd last node up is the same tree.
    while len(level) > 1:
        nxt = [sha256(b"\x01" + level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


# ---------------------------------------------------------------------------------------------------------------
# OpenTimestamps .ots (DetachedTimestampFile, major version 1, file hash op SHA-256)
# ---------------------------------------------------------------------------------------------------------------

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
OTS_MAX_ARG = 4096  # op arguments and every intermediate message
OTS_MAX_PAYLOAD = 8192
OTS_MAX_URI = 1000
OTS_MAX_DEPTH = 255  # the reference's recursion limit: a chain of at most 255 operations reads
_URI_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:")

_UNARY = {0x02: ("sha1", lambda m: hashlib.sha1(m).digest()),
          0x03: ("ripemd160", ripemd160),
          0x08: ("sha256", sha256)}
_BINARY = {0xF0: ("append", lambda m, a: m + a),
           0xF1: ("prepend", lambda m, a: a + m)}
_UNSUPPORTED = {0x67: "keccak256", 0xF2: "reverse", 0xF3: "hexlify"}


class OtsError(Exception):
    """A damaged, truncated or unsupported .ots."""


Attestation = namedtuple("Attestation", "kind value")  # kind: "bitcoin" (int height), "pending" (uri), "unknown" (tag)
OtsFile = namedtuple("OtsFile", "digest pairs")  # pairs: [(message bytes, Attestation)]


class _Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def bytes(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise OtsError("truncated")
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def byte(self):
        return self.bytes(1)[0]

    def varuint(self):
        value = shift = 0
        while True:
            b = self.byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise OtsError("varuint too long")

    def varbytes(self, max_len, min_len=0):
        n = self.varuint()
        if n > max_len or n < min_len:
            raise OtsError("length %d out of range" % n)
        return self.bytes(n)


def _attestation(r):
    tag = r.bytes(8)
    payload = _Reader(r.varbytes(OTS_MAX_PAYLOAD))
    if tag == TAG_BITCOIN:
        height = payload.varuint()
        if height > 0xFFFFFFFF:
            raise OtsError("block height too large")
        att = Attestation("bitcoin", height)
    elif tag == TAG_PENDING:
        uri = payload.varbytes(OTS_MAX_URI)
        if any(c not in _URI_CHARS for c in uri):
            raise OtsError("calendar URI with an invalid character")
        att = Attestation("pending", uri.decode("ascii"))
    else:
        return Attestation("unknown", tag.hex())
    if payload.pos != len(payload.data):
        raise OtsError("bytes after an attestation's payload")
    return att


def _timestamp(r, msg, pairs, depth, budget):
    if depth > OTS_MAX_DEPTH:
        raise OtsError("too deeply nested")
    seen = set()
    tag = r.byte()
    while True:
        more = tag == 0xFF
        item = r.byte() if more else tag
        budget[0] -= 1
        if budget[0] < 0:
            raise OtsError("too many nodes")
        if item == 0x00:
            pairs.append((msg, _attestation(r)))
        elif item in _UNARY or item in _BINARY:
            if item in _UNARY:
                key, result = (item, b""), _UNARY[item][1](msg)
            else:
                arg = r.varbytes(OTS_MAX_ARG, min_len=1)
                key, result = (item, arg), _BINARY[item][1](msg, arg)
            if key in seen:
                raise OtsError("an operation is repeated")
            seen.add(key)
            if len(result) > OTS_MAX_ARG:
                raise OtsError("a message is too long")
            _timestamp(r, result, pairs, depth + 1, budget)
        elif item in _UNSUPPORTED:
            raise OtsError("unsupported operation " + _UNSUPPORTED[item])
        else:
            raise OtsError("unknown tag 0x%02x" % item)
        if not more:
            return
        tag = r.byte()


def parse_ots(data):
    """Parse a detached timestamp -> OtsFile(digest, pairs). OtsError for anything not complete and well formed."""
    r = _Reader(data)
    if r.bytes(len(OTS_MAGIC)) != OTS_MAGIC:
        raise OtsError("not an OpenTimestamps file")
    major = r.byte()
    if major != 1:
        raise OtsError("unsupported major version %d" % major)
    if r.byte() != 0x08:
        raise OtsError("the file hash is not SHA-256")
    digest = r.bytes(32)
    pairs = []
    _timestamp(r, digest, pairs, 0, [200000])
    if r.pos != len(data):
        raise OtsError("bytes after the end of the timestamp")
    return OtsFile(digest, pairs)


# ---------------------------------------------------------------------------------------------------------------
# Bitcoin block headers from two explorers (Esplora API)
# ---------------------------------------------------------------------------------------------------------------

def compact_target(bits):
    """Bitcoin Core's SetCompact: mantissa (low 23 bits) x 256^(exponent-3); None for a negative, zero or overflowing
    one (such an nBits has no valid proof of work)."""
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    negative = mantissa != 0 and bool(bits & 0x00800000)
    overflow = mantissa != 0 and (exponent > 34 or (mantissa > 0xFF and exponent > 33) or (mantissa > 0xFFFF and exponent > 32))
    if negative or overflow:
        return None
    target = mantissa >> (8 * (3 - exponent)) if exponent <= 3 else mantissa << (8 * (exponent - 3))
    return target or None


def header_hash(raw):
    """The block hash as explorers print it: double SHA-256, reversed, hex."""
    return sha256(sha256(raw))[::-1].hex()


def has_proof_of_work(raw, limit=POW_LIMIT):
    target = compact_target(struct.unpack("<I", raw[72:76])[0])
    if target is None or target > limit:
        return False
    return int.from_bytes(sha256(sha256(raw)), "little") <= target


def http_get(url, timeout):
    """GET -> text, at most 64 kB; any problem raises."""
    req = urllib.request.Request(url, headers={"User-Agent": "mmmover-verify-proof/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise IOError("the source answered %d" % resp.status)
        body = resp.read(MAX_HTTP_BYTES + 1)
    if len(body) > MAX_HTTP_BYTES:
        raise IOError("more than 64 kB")
    return body.decode("ascii").strip()


def _hex_exact(text, n_bytes):
    if len(text) != 2 * n_bytes or not re.fullmatch(r"[0-9a-fA-F]+", text):
        raise ValueError("expected %d hex digits" % (2 * n_bytes))
    return bytes.fromhex(text)


def _header_from(source, height, get, pow_limit):
    base = source.rstrip("/")
    block_hash = _hex_exact(get("%s/block-height/%d" % (base, height)), 32).hex()
    raw = _hex_exact(get("%s/block/%s/header" % (base, block_hash)), 80)
    if header_hash(raw) != block_hash:
        raise ValueError("the header does not hash to the block hash the source gave")
    if not has_proof_of_work(raw, pow_limit):
        raise ValueError("the header has no valid proof of work")
    return raw


BlockLookup = namedtuple("BlockLookup", "header agreed conflict")


def get_header(height, sources, get, pow_limit=POW_LIMIT):
    """-> BlockLookup(header bytes | None, [sources that agreed], conflict). A source that fails is left out."""
    def one(source):
        try:
            return _header_from(source, height, get, pow_limit)
        except Exception:  # a broken or hostile explorer is never fatal
            return None
    with ThreadPoolExecutor(max_workers=max(1, len(sources))) as pool:
        got = list(pool.map(one, sources))
    answered = [(s, h) for s, h in zip(sources, got) if h is not None]
    if not answered:
        return BlockLookup(None, [], False)
    if any(h != answered[0][1] for _, h in answered):
        return BlockLookup(None, [], True)
    return BlockLookup(answered[0][1], [s for s, _ in answered], False)


BitcoinCheck = namedtuple("BitcoinCheck", "outcome height time sources problem")  # outcome: verified/mismatch/notchecked


def check_bitcoin(ots, sources, get, pow_limit=POW_LIMIT, note=None):
    """The Bitcoin attestations of `ots`, lowest height first: the first whose message is the block's merkle root is
    enough (verified); otherwise mismatch when a block's merkle root differs, notchecked when no header was had.
    At most MAX_HEIGHTS distinct heights are looked up (the lowest); `note(text)` is told when more were left out."""
    claims = sorted((att.value, msg) for msg, att in ots.pairs if att.kind == "bitcoin")
    heights = sorted({h for h, _ in claims})
    if len(heights) > MAX_HEIGHTS:
        if note:
            note("the .ots has Bitcoin attestations at %d heights — only the lowest %d were checked" % (len(heights), MAX_HEIGHTS))
        claims = [(h, m) for h, m in claims if h <= heights[MAX_HEIGHTS - 1]]
    lookups = {}
    mismatch = notchecked = None
    for height, msg in claims:
        if height not in lookups:
            lookups[height] = get_header(height, sources, get, pow_limit)
        look = lookups[height]
        if look.header is None:
            if notchecked is None:
                why = ("the block header sources disagree about block %d" if look.conflict
                       else "no block header source answered for block %d") % height
                notchecked = BitcoinCheck("notchecked", height, None, [], why)
            continue
        if msg == look.header[36:68]:
            when = struct.unpack("<I", look.header[68:72])[0]
            return BitcoinCheck("verified", height, when, look.agreed, None)
        if mismatch is None:
            mismatch = BitcoinCheck("mismatch", height, None, look.agreed, "the merkle root of block %d does not match the proof" % height)
    return mismatch or notchecked


# ---------------------------------------------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------------------------------------------

class ManifestError(Exception):
    pass


Manifest = namedtuple("Manifest", "created card_name date generation files excluded merkle_count merkle_root")
ManifestFile = namedtuple("ManifestFile", "path size sha256")  # sha256: lower-case hex


def _need(o, key, kind, low=None, high=None):
    """o[key] of type `kind` (an int also within [low, high]); ManifestError otherwise."""
    v = o.get(key) if isinstance(o, dict) else None
    ok = isinstance(v, kind) and not (kind is int and isinstance(v, bool))
    if not ok:
        raise ManifestError('missing or wrong "%s"' % key)
    if kind is int and ((low is not None and v < low) or (high is not None and v > high)):
        raise ManifestError('"%s" is out of range (%d)' % (key, v))
    return v


def _objects(o, key):
    """o[key]: a list of objects."""
    items = _need(o, key, list)
    if not all(isinstance(x, dict) for x in items):
        raise ManifestError("%s[] entry" % key)
    return items


def _prefixed(o, key, prefix, n_hex):
    s = _need(o, key, str)
    if not s.startswith(prefix) or not re.fullmatch("[0-9a-f]{%d}" % n_hex, s[len(prefix):]):
        raise ManifestError('"%s" is not %s<hex>' % (key, prefix))
    return s[len(prefix):]


def parse_manifest(data):
    """bytes -> (Manifest, the parsed JSON). ManifestError when it is not a mmMover proof manifest."""
    try:
        if data.startswith(b"\xef\xbb\xbf"):
            raise ValueError("a byte order mark")
        obj = parse_json(data.decode("utf-8"))
    except (ValueError, RecursionError) as x:
        raise ManifestError("The proof file is not valid: %s" % x)
    if not isinstance(obj, dict):
        raise ManifestError("The proof is not a JSON object.")
    if _need(obj, "format", str) != "mmmover-proof":
        raise ManifestError("Not an mmMover proof (format).")
    version = _need(obj, "version", int)
    if version > 1:
        raise ManifestError("Proof version %d is newer than this program understands." % version)
    if version != 1:
        raise ManifestError('missing or wrong "version" (%d)' % version)
    card, merkle = _need(obj, "card", dict), _need(obj, "merkle", dict)
    files = [ManifestFile(_need(f, "path", str), _need(f, "size", int, 0, MAX_INT), _prefixed(f, "sha256", "sha256:", 64))
             for f in _objects(obj, "files")]
    excluded = [(_need(e, "path", str), _need(e, "reason", str)) for e in (_objects(obj, "excluded") if "excluded" in obj else [])]
    for m in _objects(obj, "mhl"):
        _need(m, "destination", int, 1), _need(m, "path", str), _prefixed(m, "sha256", "sha256:", 64)
    return Manifest(_need(obj, "created", str), _need(card, "name", str), _need(card, "date", str),
                    _need(card, "generation", int, 1), files, excluded, _need(merkle, "count", int, 0, MAX_INT),
                    _prefixed(merkle, "root", "sha256:", 64)), obj


def manifest_root_hex(files):
    return merkle_root(ordered_leaves([(bytes.fromhex(f.sha256), f.size) for f in files])).hex()


# ---------------------------------------------------------------------------------------------------------------
# The verifier: the same lines and results as mmMover's own `mmmover proof verify`
# ---------------------------------------------------------------------------------------------------------------

REPORT_DIR = "_REPORT"
_MANIFEST_NAME = re.compile(r"offload_proof(_[0-9]{4,9})?\.json")
NO_PROOF_FILE = "no proof found: there is no _REPORT/offload_proof.json in the file's folder or any folder above it"
NO_PROOF_FOLDER = "no proof found: there is no _REPORT/offload_proof.json in this folder or any folder above it"

Verdict = namedtuple("Verdict", "outcome lines")  # outcome: "OK" | "FAILED" | "NOT YET"
Loaded = namedtuple("Loaded", "name path data manifest obj error")
ManifestCheck = namedtuple("ManifestCheck", "outcome root_ok lines reason time block")


def _L(label, text):
    return (label + ":").ljust(10) + " " + text


def _count(n, noun):
    return "1 " + noun if n == 1 else "%d %ss" % (n, noun)


def _bytes(n):
    return "1 byte" if n == 1 else "{:,} bytes".format(n)


def _utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + " UTC"


def _host(url):
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/?#]+)", url, re.I)
    return m.group(1) if m else url


def _agree(sources):
    h = [_host(s) for s in sources]
    if not h:
        return "no source answered"
    if len(h) == 1:
        return "only %s answered" % h[0]
    return "%s and %s agree" % (", ".join(h[:-1]), h[-1])


def _info(m):
    return "card %s, %s" % (m.card_name, m.date) + (", generation %d" % m.generation if m.generation > 1 else "") \
        + ", " + _count(len(m.files), "file")


def _excluded_why(reason):
    return {"source": "the card did not give the file", "destination": "it was not a good copy on every destination",
            "hash": "it had no SHA-256"}.get(reason, reason)


def _final(lines, outcome, text):
    lines.append(_L("RESULT", "%s — %s." % (outcome, text)))
    return Verdict(outcome, lines)


def _same_path(a, b):
    n = lambda s: unicodedata.normalize("NFC", s).upper()
    return n(a) == n(b)


def _hash_file(path):
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                return h.hexdigest(), size
            h.update(chunk)
            size += len(chunk)


def _manifests(card):
    report = os.path.join(card, REPORT_DIR)
    try:
        names = sorted(n for n in os.listdir(report) if _MANIFEST_NAME.fullmatch(n))
    except OSError:
        return []
    return [os.path.join(report, n) for n in sorted(names, key=lambda n: n.encode("utf-8"))]


def _find_card(directory):
    """-> (the nearest folder, this one or above, whose _REPORT holds a proof manifest, its manifests) or (None, [])."""
    d = directory
    while d:
        found = _manifests(d)
        if found:
            return d, found
        parent = os.path.dirname(d)
        if parent == d:
            return None, []
        d = parent
    return None, []


def _load(path):
    name = os.path.basename(path)
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return Loaded(name, path, b"", None, None, "%s is larger than 256 MB — not a proof manifest" % name)
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as x:
        return Loaded(name, path, b"", None, None, "%s could not be read: %s" % (name, x))
    try:
        manifest, obj = parse_manifest(data)
    except ManifestError as x:
        return Loaded(name, path, data, None, None, "%s is not a valid proof manifest (%s)" % (name, str(x).rstrip(".")))
    return Loaded(name, path, data, manifest, obj, None)


def _clock_warning(created, block_time):
    try:
        c = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return 'the manifest\'s creation time "%s" is not a time (the proof\'s time comes from Bitcoin, not from it)' % created
    d = c - block_time
    if abs(d) <= CLOCK_TOLERANCE_SECONDS:
        return None
    span = "%d hours" % int(abs(d) // 3600) if abs(d) < 72 * 3600 else "%d days" % int(abs(d) // 86400)
    if d > 0:
        return ("the manifest says it was created %s, %s after the Bitcoin block — the computer's clock was wrong "
                "(the proof stays valid: its time comes from Bitcoin, not from that clock)" % (_utc(c), span))
    return ("the manifest says it was created %s, %s before the Bitcoin block — the computer's clock was wrong or the "
            "proof waited that long for the network (the proof stays valid: its time comes from Bitcoin, not from "
            "that clock)" % (_utc(c), span))


def _check_manifest(m, offline, sources, get, pow_limit):
    """One manifest's own checks. Whatever a hostile manifest still makes raise is FAILED -- not a valid proof manifest,
    never an exception."""
    try:
        return _check_manifest_raw(m, offline, sources, get, pow_limit)
    except (ValueError, TypeError, KeyError, ManifestError) as x:
        return ManifestCheck("FAILED", False, [], "%s is not a valid proof manifest (%s)" % (m.name, str(x).rstrip(".")), None, None)


def _check_manifest_raw(m, offline, sources, get, pow_limit):
    man = m.manifest
    lines = []
    if jcs_bytes(m.obj) != m.data:
        return ManifestCheck("FAILED", False, lines, "the manifest is not canonical — it was edited", None, None)
    if manifest_root_hex(man.files) != man.merkle_root:
        return ManifestCheck("FAILED", False, lines, "the Merkle root in the manifest does not match its files", None, None)
    if man.merkle_count != len(man.files):
        return ManifestCheck("FAILED", False, lines, "the file count in the manifest (%d) does not match its files (%d)"
                             % (man.merkle_count, len(man.files)), None, None)
    ots_name = m.name + ".ots"
    ots_path = m.path + ".ots"
    if not os.path.isfile(ots_path):
        lines.append(_L("Anchor", "none yet — %s is not next to the manifest" % ots_name))
        return ManifestCheck("NOT YET", True, lines, "there is no timestamp (%s) next to the manifest, so nothing proves "
                             "yet when the files existed" % ots_name, None, None)
    try:
        if os.path.getsize(ots_path) > MAX_OTS_BYTES:
            raise OtsError("larger than 4 MB")
        with open(ots_path, "rb") as fh:
            ots = parse_ots(fh.read())
    except OtsError as x:
        return ManifestCheck("FAILED", True, lines, "%s is not a valid timestamp (%s)" % (ots_name, x), None, None)
    except OSError as x:
        return ManifestCheck("FAILED", True, lines, "%s could not be read: %s" % (ots_name, x), None, None)
    if ots.digest != sha256(m.data):
        return ManifestCheck("FAILED", True, lines, "the manifest changed after it was anchored (its SHA-256 is not the "
                             "one %s was made for)" % ots_name, None, None)

    heights = [a.value for _, a in ots.pairs if a.kind == "bitcoin"]
    pending = list(dict.fromkeys(a.value for _, a in ots.pairs if a.kind == "pending"))
    if not heights:
        if not pending:
            return ManifestCheck("FAILED", True, lines, "%s has no Bitcoin attestation and no calendar that could give "
                                 "one" % ots_name, None, None)
        lines.append(_L("Anchor", "pending at %s (%s) — not in Bitcoin yet"
                        % (_count(len(pending), "calendar"), ", ".join(_host(p) for p in pending))))
        return ManifestCheck("NOT YET", True, lines, "the timestamp is not in Bitcoin yet (Bitcoin confirms it a few hours "
                             "after the copy; mmmover proof upgrade <card folder> asks the calendars)", None, None)
    claimed = min(heights)
    if offline:
        lines.append(_L("Anchor", "Bitcoin block %d (in %s; not checked — offline)" % (claimed, ots_name)))
        return ManifestCheck("NOT YET", True, lines, "the Bitcoin block was not checked (offline)", None, claimed)

    notes = []
    check = check_bitcoin(ots, sources, get, pow_limit, note=notes.append)
    lines.extend(_L("Warning", n) for n in notes)
    if check.outcome == "verified":
        lines.append(_L("Anchor", "Bitcoin block %d, %s (%s)" % (check.height, _utc(check.time), _agree(check.sources))))
        if len(check.sources) == 1:
            lines.append(_L("Warning", "only one block header source answered — the header could not be compared with a second one"))
        warn = _clock_warning(man.created, check.time)
        if warn:
            lines.append(_L("Warning", warn))
        return ManifestCheck("OK", True, lines, "", check.time, check.height)
    if check.outcome == "mismatch":
        lines.append(_L("Anchor", "Bitcoin block %d — its merkle root is not the one in %s" % (check.height, ots_name)))
        return ManifestCheck("FAILED", True, lines, "a Bitcoin attestation in the .ots does not match block %d" % check.height,
                             None, check.height)
    lines.append(_L("Anchor", "Bitcoin block %d (in %s) — not checked: %s" % (check.height, ots_name, check.problem)))
    return ManifestCheck("NOT YET", True, lines, "the Bitcoin block could not be checked — try again later", None, check.height)


def _relative(card, full):
    return os.path.relpath(full, card).replace("\\", "/")


def verify_file(file, offline=False, sources=None, timeout=10, get=None, pow_limit=POW_LIMIT):
    """One file: its SHA-256 and size must be in a manifest of the card folder above it, and that manifest's proof must
    hold. -> Verdict(outcome, lines). Disk and network problems are lines, never exceptions."""
    sources = HEADER_SOURCES if sources is None else sources
    get = get or (lambda url: http_get(url, timeout))
    lines = []
    full = os.path.abspath(file)
    if not os.path.isfile(full):
        lines.append(_L("File", file))
        return _final(lines, "FAILED", "the file is not there")
    card, found = _find_card(os.path.dirname(full))
    rel = _relative(card, full) if card else os.path.basename(full)
    lines.append(_L("File", rel))
    try:
        digest, size = _hash_file(full)
    except OSError as x:
        return _final(lines, "FAILED", "the file could not be read: %s" % x)
    if card is None:
        lines.append(_L("SHA-256", digest))
        return _final(lines, "FAILED", NO_PROOF_FILE)

    loaded = [_load(p) for p in found]
    matches = []
    for m in loaded:
        if m.manifest is None:
            continue
        hits = [f for f in m.manifest.files if f.size == size and f.sha256 == digest]
        if hits:
            matches.append((m, next((f for f in hits if _same_path(f.path, rel)), hits[0])))
    unreadable = [m for m in loaded if m.error]
    if not matches:
        lines.append(_L("SHA-256", digest))
        if not loaded:
            return _final(lines, "FAILED", NO_PROOF_FILE)
        if len(unreadable) == len(loaded):
            return _final(lines, "FAILED", unreadable[0].error)
        for m in loaded:
            if m.manifest is None:
                continue
            for f in m.manifest.files:
                if _same_path(f.path, rel):
                    lines.append(_L("Note", "%s lists %s with SHA-256 %s (%s) — this file is not that one (changed or replaced)"
                                    % (m.name, f.path, f.sha256, _bytes(f.size))))
            for path, reason in m.manifest.excluded:
                if _same_path(path, rel):
                    lines.append(_L("Note", "%s left %s out when it was made (%s)" % (m.name, path, _excluded_why(reason))))
        for m in unreadable:
            lines.append(_L("Warning", m.error))
        return _final(lines, "FAILED", "SHA-256 does not match any file of the proof")

    checks = []
    for m, entry in matches:
        c = _check_manifest(m, offline, sources, get, pow_limit)
        checks.append(c)
        lines.append(_L("SHA-256", "%s  — matches %s (%s%s)" % (digest, m.name, _info(m.manifest), ", Merkle root OK" if c.root_ok else "")))
        if not _same_path(entry.path, rel):
            lines.append(_L("Note", "listed as %s (renamed or moved)" % entry.path))
            for f in m.manifest.files:
                if _same_path(f.path, rel) and f.sha256 != digest:
                    lines.append(_L("Warning", "%s lists %s with another SHA-256 (%s) — this file has the content of %s, "
                                    "not of the file that was at this path" % (m.name, f.path, f.sha256, entry.path)))
        lines.extend(c.lines)
    for m in unreadable:
        lines.append(_L("Warning", m.error))

    failed = next((c for c in checks if c.outcome == "FAILED"), None)
    if failed:
        return _final(lines, "FAILED", failed.reason)
    oks = sorted((c for c in checks if c.outcome == "OK"), key=lambda c: c.time)
    if oks:
        return _final(lines, "OK", "this file existed unchanged no later than %s" % _utc(oks[0].time))
    return _final(lines, "NOT YET", checks[0].reason)


def _resolve(card, rel):
    """A manifest path inside the card folder; None for one that leads out of it."""
    if not rel or "\\" in rel or ":" in rel or rel.startswith("/"):
        return None
    root = os.path.abspath(card).rstrip("\\/") + os.sep
    full = os.path.abspath(os.path.join(root, rel.replace("/", os.sep)))
    return full if os.path.normcase(full).startswith(os.path.normcase(root)) else None


def verify_folder(folder, offline=False, sources=None, timeout=10, get=None, pow_limit=POW_LIMIT):
    """A card folder: every manifest's proof checked and every file of every manifest hashed again."""
    sources = HEADER_SOURCES if sources is None else sources
    get = get or (lambda url: http_get(url, timeout))
    lines = []
    full = os.path.abspath(folder)
    if not os.path.isdir(full):
        lines.append(_L("Card", folder))
        return _final(lines, "FAILED", "the folder is not there")
    card, found = _find_card(full)
    lines.append(_L("Card", card or full))
    if card is None or not found:
        return _final(lines, "FAILED", NO_PROOF_FOLDER)
    loaded = [_load(p) for p in found]
    several = len(loaded) > 1
    ok = changed = missing = unreadable = 0
    failures, waiting, anchors = [], [], []
    for m in loaded:
        if m.manifest is None:
            lines.append(_L("Proof", m.name))
            failures.append(m.error)
            continue
        c = _check_manifest(m, offline, sources, get, pow_limit)
        lines.append(_L("Proof", "%s (%s%s)" % (m.name, _info(m.manifest), ", Merkle root OK" if c.root_ok else "")))
        lines.extend(c.lines)
        if m.manifest.excluded:
            n = len(m.manifest.excluded)
            lines.append(_L("Note", "%s of that copy %s not in the proof (left out when it was made)"
                            % (_count(n, "file"), "is" if n == 1 else "are")))
        why = "%s: %s" % (m.name, c.reason) if several else c.reason
        if c.outcome == "FAILED":
            failures.append(why)
        elif c.outcome == "NOT YET":
            waiting.append(why)
        else:
            anchors.append(c.time)
        for f in m.manifest.files:
            path = _resolve(card, f.path)
            if path is None:
                missing += 1
                lines.append(_L("Missing", "%s (not a path inside the card folder)" % f.path))
                continue
            try:
                if not os.path.isfile(path):
                    missing += 1
                    lines.append(_L("Missing", f.path))
                    continue
                if os.path.getsize(path) != f.size or _hash_file(path)[0] != f.sha256:
                    changed += 1
                    lines.append(_L("Changed", f.path))
                    continue
                ok += 1
            except OSError as x:
                unreadable += 1
                lines.append(_L("Unreadable", "%s: %s" % (f.path, x)))
    lines.append(_L("Files", "%s OK, %d changed, %d missing" % (_count(ok, "file"), changed, missing)
                    + (", %d unreadable" % unreadable if unreadable else "")))
    if changed + missing + unreadable:
        parts = [(n, w) for n, w in ((changed, "changed"), (missing, "missing"), (unreadable, "unreadable")) if n]
        failures.append(", ".join(("%s" % (_count(n, "file") if i == 0 else n)) + " " + w for i, (n, w) in enumerate(parts))
                        + " since the proof was made")
    if failures:
        return _final(lines, "FAILED", "; ".join(failures))
    every = "the file" if ok == 1 else "all %d files" % ok
    if waiting or not anchors:
        return _final(lines, "NOT YET", "%s %s unchanged, but %s" % (every, "is" if ok == 1 else "are",
                                                                    "; ".join(waiting) if waiting else "no proof is anchored"))
    return _final(lines, "OK", "%s existed unchanged no later than %s" % (every, _utc(max(anchors))))


# ---------------------------------------------------------------------------------------------------------------
# Test vectors shared with the C# implementation (shared/proof/vectors.json)
# ---------------------------------------------------------------------------------------------------------------

CT_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
VECTOR_COUNTS = [0, 1, 2, 3, 2001]

# (JSON text, canonical text) -- written by hand from RFC 8785; make_vectors() checks that jcs() agrees.
JCS_CASES = [
    ('{"b":2,"a":"\\u20ac\\n\\u0001","c":[true,false,null],"\\u20ac":1,"\\r":0}',
     '{"\\r":0,"a":"€\\n\\u0001","b":2,"c":[true,false,null],"€":1}'),
    ('{ "a" : [ 1 , 2 ] ,\n "b" : { } , "c" : [ ] }', '{"a":[1,2],"b":{},"c":[]}'),
    # U+1F600 is the surrogate pair D83D DE00, which sorts before U+FF5E (RFC 8785 3.2.3), unlike UTF-8 order.
    ('{"\\uff5e":1,"\\ud83d\\ude00":2}', '{"\U0001F600":2,"～":1}'),
    ('{"\\ud83d\\ude00":"\\ud83d\\ude00"}', '{"\U0001F600":"\U0001F600"}'),
    ('["\\ud800"]', '["\\ud800"]'),
    ('["\\ud83d\\ude00\\udc00"]', '["\U0001F600\\udc00"]'),
    ('"\\u0000\\u0008\\u0009\\u000a\\u000c\\u000d\\u001F\\u007f\\u2028\\"\\\\\\/"',
     '"\\u0000\\b\\t\\n\\f\\r\\u001f\x7f \\"\\\\/"'),
    ('["\\u00E9","\\u001F","\\u001f"]', '["é","\\u001f","\\u001f"]'),
    ('[0,-5,9007199254740991,-9007199254740991]', '[0,-5,9007199254740991,-9007199254740991]'),
    ('{"path":"Záznam/Česká žluťoučká.mov","size":10}',
     '{"path":"Záznam/Česká žluťoučká.mov","size":10}'),
    ('{"p":"CLIP/\U0001F600 試驗.mov","o":"é.mov","n":"é.mov"}',
     '{"n":"é.mov","o":"é.mov","p":"CLIP/\U0001F600 試驗.mov"}'),
    ('{"files":[{"size":7,"path":"ž/š.mov"},{"path":"\U0001F600.mov","size":8}],"complete":true}',
     '{"complete":true,"files":[{"path":"ž/š.mov","size":7},{"path":"\U0001F600.mov","size":8}]}'),
]


def make_vectors():
    ct = []
    for n in range(0, len(CT_LEAVES) + 1):
        data = [bytes.fromhex(h) for h in CT_LEAVES[:n]]
        ct.append({"count": n, "data": CT_LEAVES[:n], "root": merkle_root(data).hex()})
    merkle = []
    for n in VECTOR_COUNTS:
        leaves = [(sha256(str(i).encode("ascii")), i * 1000 + 7) for i in range(n)]
        merkle.append({"count": n,
                       "leaves": [{"sha256": s.hex(), "size": size} for s, size in leaves],
                       "root": merkle_root(ordered_leaves(leaves)).hex()})
    cases = []
    for text, canonical in JCS_CASES:
        got = jcs(parse_json(text))
        if got != canonical:
            raise AssertionError("JCS case disagrees with its hand-written result: %r -> %r, expected %r" % (text, got, canonical))
        cases.append({"json": text, "canonical": canonical})
    return {"merkle": merkle, "ct": ct, "jcs": cases}


def vectors_text():
    return json.dumps(make_vectors(), indent=1, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(prog="verify_proof.py", description="Verify an mmMover Offload Proof (standard library only).")
    p.add_argument("path", nargs="?", help="a file from a card, or a card folder")
    p.add_argument("--offline", action="store_true", help="only say what the .ots contains; ask no block explorer")
    p.add_argument("--make-vectors", metavar="OUT.json", help="write the shared test vectors and exit")
    p.add_argument("--timeout", type=float, default=10.0, help="seconds per block explorer request (default 10)")
    args = p.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    if args.make_vectors:
        with open(args.make_vectors, "w", encoding="ascii", newline="\n") as fh:
            fh.write(vectors_text())
        return EXIT_OK
    if not args.path:
        p.error("give a file or a card folder")
    run = verify_folder if os.path.isdir(args.path) else verify_file
    verdict = run(args.path, offline=args.offline, timeout=args.timeout)
    for line in verdict.lines:
        print(line)
    return {"OK": EXIT_OK, "FAILED": EXIT_FAILED}.get(verdict.outcome, EXIT_NOT_YET)


if __name__ == "__main__":
    sys.exit(main())
