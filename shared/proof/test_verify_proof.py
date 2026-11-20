"""Tests of verify_proof.py. Run from the repo root:  python -m unittest shared/proof/test_verify_proof.py -v

Standard library only; no network (block explorers are faked with a function)."""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_proof as vp  # noqa: E402

VECTORS = os.path.join(HERE, "vectors.json")
CRLF, LF = b"\r\n", b"\n"  # a checkout with autocrlf may turn the vectors' line ends into CRLF

# hello-world.txt.ots of python-opentimestamps: SHA-256 root, uses ripemd160, ends in Bitcoin block 358391.
HELLO_WORLD_OTS = bytes.fromhex(
    "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294010803ba204e50d126e4674c005e04d82e84c21366780af1f4"
    "3bd54a37816b6ab34003f1c8010100000001e482f9d32ecc3ba657b69d898010857b54457a90497982ff56f97c4ec58e6f98010000006b48"
    "3045022100b253add1d1cf90844338a475a04ff13fc9e7bd242b07762dea07f5608b2de367022000b268ca9c3342b3769cdd062891317cd"
    "cef87aac310b6855e9d93898ebbe8ec0121020d8e4d107d2b339b0050efdd4b4a09245aa056048f125396374ea6a2ab0709c6ffffffff02"
    "6533e605000000001976a9140bf057d40fbba6744862515f5b55a2310de5772f88aca0860100000000001976a914f00688ac000000000808"
    "f120a987f716c533913c314c78e35d35884cac943fa42cac49d2b2c69f4003f85f880808f120dec55b3487e1e3f722a49b55a7783215862"
    "785f4a3acb392846019f71dc64a9d0808f120b2ca18f485e080478e025dab3d464b416c0e1ecb6629c9aefce8c8214d0424320808f02011"
    "b0e90661196ff4b0813c3eda141bab5e91604837bdf7a0c9df37db0e3a11980808f020c34bc1a4a1093ffd148c016b1e664742914e939ef"
    "abe4d3d356515914b26d9e20808f020c3e6e7c38c69f6af24c2be34ebac48257ede61ec0a21b9535e4443277be306460808f1200798bf86"
    "06e00024e5d5d54bf0c960f629dfb9dad69157455b6f2652c0e8de810808f0203f9ada6d60baa244006bb0aad51448ad2fafb9d4b6487a09"
    "99cff26b91f0f5360808f120c703019e959a8dd3faef7489bb328ba485574758e7091f01464eb65872c975c80808f020cbfefff513ff84b"
    "915e3fed6f9d799676630f8364ea2a6c7557fad94a5b5d7880808f1200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8ac"
    "fdf093b7050808000588960d73d7190103f7ef15")
HELLO_WORLD_SHA256 = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340"

# incomplete.txt.ots: a pending attestation at alice.btc.calendar.opentimestamps.org.
INCOMPLETE_OTS = bytes.fromhex(
    "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294010805c4f616a8e5310d19d938cfd769864d7f4ccdc2ca8b47"
    "9b10af83564b097af9f010e754bf93806a7ebaa680ef7bd0114bf408f010b573e8850cfd9e63d1f043fbb6fc250e08f10457cfa5c4f0086f"
    "b1ac8d4e4eb0e70083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d65737461"
    "6d70732e6f7267")

NONCE = bytes(range(0xA0, 0xB0))
REGTEST_LIMIT = 1 << 255
EASY_BITS = 0x207FFFFF


def sha(data):
    return hashlib.sha256(data).digest()


class Ripemd160Tests(unittest.TestCase):
    def test_pure_vectors(self):
        self.assertEqual(vp.ripemd160_pure(b"").hex(), "9c1185a5c5e9fc54612808977ee8f548b2258d31")
        self.assertEqual(vp.ripemd160_pure(b"abc").hex(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        self.assertEqual(vp.ripemd160_pure(b"message digest").hex(), "5d0689ef49d2fae572b881b123a85ffa21595f36")

    def test_front_end_agrees_with_pure(self):
        for data in (b"", b"abc", bytes(range(256)) * 3):
            self.assertEqual(vp.ripemd160(data), vp.ripemd160_pure(data))

    def test_hashlib_agrees_when_available(self):
        try:
            h = hashlib.new("ripemd160", b"abc").digest()
        except ValueError:
            self.skipTest("this OpenSSL has no ripemd160")
        self.assertEqual(h, vp.ripemd160_pure(b"abc"))


class MerkleTests(unittest.TestCase):
    CT_ROOTS = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ]

    def test_certificate_transparency_roots(self):
        data = [bytes.fromhex(h) for h in vp.CT_LEAVES]
        for n in range(1, 9):
            self.assertEqual(vp.merkle_root(data[:n]).hex(), self.CT_ROOTS[n - 1], n)
        self.assertEqual(vp.merkle_root([]).hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_matches_rfc6962_recursive_definition(self):
        def mth(d):
            if not d:
                return sha(b"")
            if len(d) == 1:
                return sha(b"\x00" + d[0])
            k = 1
            while k * 2 < len(d):
                k *= 2
            return sha(b"\x01" + mth(d[:k]) + mth(d[k:]))
        for n in list(range(0, 40)) + [63, 64, 65, 100, 129]:
            data = [bytes([i % 251]) * (i % 7) for i in range(n)]
            self.assertEqual(vp.merkle_root(data), mth(data), n)

    def test_leaf_order_and_data(self):
        a, b = sha(b"a"), sha(b"b")
        lo, hi = sorted([a, b])
        self.assertEqual(vp.ordered_leaves([(hi, 1), (lo, 9), (lo, 2)]),
                         [lo + struct.pack(">Q", 2), lo + struct.pack(">Q", 9), hi + struct.pack(">Q", 1)])
        self.assertEqual(len(vp.leaf_data(a, 5)), 40)
        # the same file twice = two leaves
        self.assertEqual(len(vp.ordered_leaves([(a, 1), (a, 1)])), 2)

    def test_20000_leaves_are_fast(self):
        leaves = [(sha(str(i).encode()), i) for i in range(20000)]
        t = time.perf_counter()
        root = vp.merkle_root(vp.ordered_leaves(leaves))
        self.assertLess(time.perf_counter() - t, 1.5)
        self.assertEqual(len(root), 32)


class VectorsTests(unittest.TestCase):
    def test_make_vectors_reproduces_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "v.json")
            self.assertEqual(vp.main(["--make-vectors", out]), 0)
            with open(out, "rb") as a, open(VECTORS, "rb") as b:
                self.assertEqual(a.read(), b.read().replace(CRLF, LF))

    def test_make_vectors_through_the_command_line(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "v.json")
            subprocess.run([sys.executable, "-I", os.path.join(HERE, "verify_proof.py"), "--make-vectors", out], check=True)
            with open(out, "rb") as a, open(VECTORS, "rb") as b:
                self.assertEqual(a.read(), b.read().replace(CRLF, LF))

    def test_vector_file_shape(self):
        import json
        with open(VECTORS, encoding="ascii") as fh:
            v = json.load(fh)
        self.assertEqual([m["count"] for m in v["merkle"]], [0, 1, 2, 3, 2001])
        for m in v["merkle"]:
            self.assertEqual(len(m["leaves"]), m["count"])
        self.assertEqual([c["count"] for c in v["ct"]], list(range(0, 9)))
        self.assertGreaterEqual(len(v["jcs"]), 10)
        # leaf i: SHA-256 of the ASCII decimal i, size i * 1000 + 7
        leaf = v["merkle"][4]["leaves"][1234]
        self.assertEqual(leaf, {"sha256": sha(b"1234").hex(), "size": 1234007})

    def test_every_vector_recomputes(self):
        import json
        with open(VECTORS, encoding="ascii") as fh:
            v = json.load(fh)
        for m in v["merkle"]:
            files = [(bytes.fromhex(x["sha256"]), x["size"]) for x in m["leaves"]]
            self.assertEqual(vp.merkle_root(vp.ordered_leaves(files)).hex(), m["root"])
        for c in v["ct"]:
            self.assertEqual(vp.merkle_root([bytes.fromhex(h) for h in c["data"]]).hex(), c["root"])
        for c in v["jcs"]:
            self.assertEqual(vp.jcs(vp.parse_json(c["json"])), c["canonical"])


class JcsTests(unittest.TestCase):
    def test_keys_by_utf16_units(self):
        # U+1F600 = D83D DE00 sorts before U+FF5E in UTF-16, after it in UTF-8
        self.assertEqual(vp.jcs({"\uff5e": 1, "\U0001F600": 2}), '{"\U0001F600":2,"\uff5e":1}')

    def test_string_escapes_are_lower_case_and_minimal(self):
        self.assertEqual(vp.jcs_string("\x00\x08\x09\x0a\x0c\x0d\x1f\x7f\"\\/"), '"\\u0000\\b\\t\\n\\f\\r\\u001f\x7f\\"\\\\/"')
        self.assertEqual(vp.jcs_string("\ud800"), '"\\ud800"')
        self.assertEqual(vp.jcs_string("\udfff"), '"\\udfff"')
        self.assertEqual(vp.jcs_string("\U0001F600\u2028"), '"\U0001F600\u2028"')

    def test_not_python_json_dumps(self):
        # json.dumps(ensure_ascii=False) writes DEL / U+2028 literally too, but a lone surrogate would stay raw
        import json
        self.assertNotEqual(json.dumps("\ud800", ensure_ascii=False), vp.jcs_string("\ud800"))

    def test_numbers(self):
        self.assertEqual(vp.jcs([0, -5, 9007199254740991]), "[0,-5,9007199254740991]")
        with self.assertRaises(ValueError):
            vp.jcs(9007199254740992)
        with self.assertRaises(ValueError):
            vp.parse_json("1.5")
        with self.assertRaises(ValueError):
            vp.parse_json("1e3")
        with self.assertRaises(ValueError):
            vp.parse_json('{"a":1,"a":2}')

    def test_utf8_output_without_bom(self):
        b = vp.jcs_bytes({"k": "š", "p": "\U0001F600"})
        self.assertEqual(b, '{"k":"š","p":"\U0001F600"}'.encode("utf-8"))


class OtsParseTests(unittest.TestCase):
    def test_hello_world(self):
        ots = vp.parse_ots(HELLO_WORLD_OTS)
        self.assertEqual(ots.digest.hex(), HELLO_WORLD_SHA256)
        self.assertEqual([a.value for _, a in ots.pairs if a.kind == "bitcoin"], [358391])
        self.assertEqual(len(ots.pairs), 1)

    def test_incomplete_is_pending(self):
        ots = vp.parse_ots(INCOMPLETE_OTS)
        self.assertEqual([(a.kind, a.value) for _, a in ots.pairs], [("pending", "https://alice.btc.calendar.opentimestamps.org")])

    def test_every_truncation_and_trailing_byte_is_an_error(self):
        for n in range(len(INCOMPLETE_OTS)):
            with self.assertRaises(vp.OtsError):
                vp.parse_ots(INCOMPLETE_OTS[:n])
        with self.assertRaises(vp.OtsError):
            vp.parse_ots(INCOMPLETE_OTS + b"\x00")

    def test_bad_magic_version_and_file_hash(self):
        bad = bytearray(INCOMPLETE_OTS)
        bad[0] ^= 1
        with self.assertRaises(vp.OtsError):
            vp.parse_ots(bytes(bad))
        bad = bytearray(INCOMPLETE_OTS)
        bad[31] = 2
        with self.assertRaises(vp.OtsError):
            vp.parse_ots(bytes(bad))
        bad = bytearray(INCOMPLETE_OTS)
        bad[32] = 0x02  # sha1 as file hash op
        with self.assertRaises(vp.OtsError):
            vp.parse_ots(bytes(bad))

    def _file(self, tail):
        return vp.OTS_MAGIC + b"\x01\x08" + b"\x11" * 32 + tail

    def test_unsupported_and_unknown_ops(self):
        for tag in (0x67, 0xF2, 0xF3, 0x55):
            with self.assertRaises(vp.OtsError):
                vp.parse_ots(self._file(bytes([tag])))

    def test_unknown_attestation_is_kept_not_fatal(self):
        ots = vp.parse_ots(self._file(b"\x00" + b"\x01" * 8 + b"\x02ab"))
        self.assertEqual([a.kind for _, a in ots.pairs], ["unknown"])

    def test_repeated_op_and_huge_argument_and_depth(self):
        att = b"\x00" + vp.TAG_PENDING + b"\x04\x03abc"
        # append(01) twice at one node
        twice = b"\xff\xf0\x01\x01" + att + b"\xf0\x01\x01" + att
        with self.assertRaises(vp.OtsError):
            vp.parse_ots(self._file(twice))
        with self.assertRaises(vp.OtsError):
            vp.parse_ots(self._file(b"\xf0\xff\xff\x7f"))  # argument length 2^21
        deep = b"\x08" * 300 + att
        with self.assertRaises(vp.OtsError):
            vp.parse_ots(self._file(deep))

    def test_ops_compute(self):
        att = b"\x00" + vp.TAG_BITCOIN + b"\x01\x07"
        ots = vp.parse_ots(self._file(b"\xff\xf0\x02ab" + att + b"\xf1\x01c" + att))
        self.assertEqual({m for m, _ in ots.pairs}, {b"\x11" * 32 + b"ab", b"c" + b"\x11" * 32})


def mine(merkle_root, when, bits=EASY_BITS, prev=b"\x00" * 32):
    """An 80-byte header at regtest difficulty whose merkle root is `merkle_root`."""
    for nonce in range(1 << 20):
        raw = struct.pack("<I", 0x20000000) + prev + merkle_root + struct.pack("<III", when, bits, nonce)
        if vp.has_proof_of_work(raw, REGTEST_LIMIT):
            return raw
    raise AssertionError("no nonce")


def explorer(headers, fail=(), lie=None):
    """A fake `get(url)` over {height: raw header}. `fail`: URL prefixes that raise; `lie`: {prefix: {height: raw}}."""
    def get(url):
        for p in fail:
            if url.startswith(p):
                raise IOError("down")
        table = headers
        for p, t in (lie or {}).items():
            if url.startswith(p):
                table = t
        if "/block-height/" in url:
            raw = table[int(url.rsplit("/", 1)[1])]
            return vp.header_hash(raw)
        if url.endswith("/header"):
            h = url.split("/block/")[1].split("/")[0]
            for raw in table.values():
                if vp.header_hash(raw) == h:
                    return raw.hex()
        raise IOError("404")
    return get


A, B = "https://a.example/api", "https://b.example/api"


class BitcoinTests(unittest.TestCase):
    def setUp(self):
        self.msg = sha(b"commitment")
        self.when = 1700000000
        self.header = mine(self.msg, self.when)
        self.ots = vp.OtsFile(b"\0" * 32, [(self.msg, vp.Attestation("bitcoin", 800000))])

    def check(self, get, sources=(A, B), ots=None):
        return vp.check_bitcoin(ots or self.ots, list(sources), get, REGTEST_LIMIT)

    def test_verified_by_two_sources(self):
        c = self.check(explorer({800000: self.header}))
        self.assertEqual((c.outcome, c.height, c.time, c.sources), ("verified", 800000, self.when, [A, B]))

    def test_one_source_only(self):
        c = self.check(explorer({800000: self.header}, fail=[B]))
        self.assertEqual((c.outcome, c.sources), ("verified", [A]))

    def test_no_source_answers(self):
        c = self.check(explorer({800000: self.header}, fail=[A, B]))
        self.assertEqual(c.outcome, "notchecked")

    def test_sources_disagree(self):
        other = mine(sha(b"other"), self.when)
        c = self.check(explorer({800000: self.header}, lie={B: {800000: other}}))
        self.assertEqual(c.outcome, "notchecked")
        self.assertIn("disagree", c.problem)

    def test_wrong_merkle_root_is_mismatch(self):
        ots = vp.OtsFile(b"\0" * 32, [(sha(b"not it"), vp.Attestation("bitcoin", 800000))])
        self.assertEqual(self.check(explorer({800000: self.header}), ots=ots).outcome, "mismatch")

    def test_header_that_does_not_hash_to_the_block_hash_is_left_out(self):
        def get(url):
            if "/block-height/" in url:
                return "ab" * 32
            return self.header.hex()
        self.assertEqual(self.check(get).outcome, "notchecked")

    def test_header_without_proof_of_work_is_left_out(self):
        raw = bytearray(mine(self.msg, self.when))
        for nonce in range(1 << 12):
            raw[76:80] = struct.pack("<I", nonce)
            if not vp.has_proof_of_work(bytes(raw), REGTEST_LIMIT):
                break
        # the same header at the real Bitcoin limit has no proof of work either
        self.assertFalse(vp.has_proof_of_work(bytes(raw), vp.POW_LIMIT))
        c = vp.check_bitcoin(self.ots, [A], explorer({800000: bytes(raw)}), vp.POW_LIMIT)
        self.assertEqual(c.outcome, "notchecked")

    def test_lowest_height_first_and_one_verified_is_enough(self):
        ots = vp.OtsFile(b"\0" * 32, [(self.msg, vp.Attestation("bitcoin", 800005)), (self.msg, vp.Attestation("bitcoin", 800000))])
        c = self.check(explorer({800000: self.header}), ots=ots)
        self.assertEqual((c.outcome, c.height), ("verified", 800000))

    def test_compact_targets(self):
        self.assertEqual(vp.compact_target(0x1D00FFFF), 0xFFFF << (8 * 26))
        self.assertEqual(vp.compact_target(0x1D00FFFF) >> 0, (0xFFFF << 208))
        self.assertEqual(vp.compact_target(0x03123456), 0x123456)
        self.assertEqual(vp.compact_target(0x02123456), 0x1234)
        self.assertEqual(vp.compact_target(0x01123456), 0x12)
        self.assertIsNone(vp.compact_target(0x01803456))  # negative
        self.assertIsNone(vp.compact_target(0x04923456))  # negative
        self.assertIsNone(vp.compact_target(0x00000000))  # zero
        self.assertIsNone(vp.compact_target(0x01000000))  # zero mantissa
        self.assertIsNone(vp.compact_target(0xFF123456))  # overflow
        self.assertIsNone(vp.compact_target(0x23000001))  # exponent 35 overflows
        self.assertEqual(vp.compact_target(0x2100FFFF), 0xFFFF << (8 * 30))
        self.assertIsNone(vp.compact_target(0x2200FFFF))  # 36 bytes

    def test_genesis_block_header(self):
        raw = bytes.fromhex(
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3"
            "888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c")
        self.assertEqual(vp.header_hash(raw), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
        self.assertTrue(vp.has_proof_of_work(raw))
        self.assertFalse(vp.has_proof_of_work(raw[:76] + b"\x00\x00\x00\x00"))


class CardFolder:
    """A card folder `<tmp>/A001` with clips and `_REPORT/offload_proof.json`, written with this verifier's own JCS."""

    def __init__(self, tmp, files=None, created="2026-11-19T21:30:00Z", write_clips=True):
        self.card = os.path.join(tmp, "A001")
        self.files = files or {
            "CLIP/A.mov": os.urandom(3000),
            "CLIP/\u010cesk\u00e1 \u017e.mov": b"czech" * 100,
            "CLIP/\U0001F600.mov": b"emoji",
        }
        for rel, data in (self.files.items() if write_clips else ()):
            p = os.path.join(self.card, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(data)
        entries = sorted(({"path": r, "size": len(d), "sha256": "sha256:" + sha(d).hex(), "xxh64": "xxh64:0123456789abcdef"}
                          for r, d in self.files.items()), key=lambda e: e["path"].encode("utf-16-be", "surrogatepass"))
        root = vp.merkle_root(vp.ordered_leaves([(sha(d), len(d)) for d in self.files.values()])).hex()
        self.obj = {"format": "mmmover-proof", "version": 1, "id": "5f0c2e0e-1111-4222-8333-444455556666", "created": created,
                    "tool": {"name": "mmMover", "version": "test", "platform": "windows"}, "machine": "PC",
                    "card": {"name": "A001", "date": "2026-11-19", "source": "E:\\", "generation": 1}, "complete": True,
                    "files": entries, "merkle": {"scheme": "rfc6962-sha256", "count": len(entries), "root": "sha256:" + root},
                    "mhl": []}
        self.write_manifest()

    @property
    def manifest(self):
        return os.path.join(self.card, "_REPORT", "offload_proof.json")

    def clip(self, rel):
        return os.path.join(self.card, *rel.split("/"))

    def write_manifest(self, data=None):
        os.makedirs(os.path.dirname(self.manifest), exist_ok=True)
        with open(self.manifest, "wb") as fh:
            fh.write(data if data is not None else vp.jcs_bytes(self.obj))

    def manifest_bytes(self):
        with open(self.manifest, "rb") as fh:
            return fh.read()

    def write_ots(self, tail, digest=None):
        with open(self.manifest + ".ots", "wb") as fh:
            fh.write(vp.OTS_MAGIC + b"\x01\x08" + (digest or sha(self.manifest_bytes())) + tail)

    def commitment(self):
        return sha(sha(self.manifest_bytes()) + NONCE)

    def write_complete_ots(self, height=800000):
        payload = self._varuint(height)
        self.write_ots(b"\xf0\x10" + NONCE + b"\x08" + b"\x00" + vp.TAG_BITCOIN + bytes([len(payload)]) + payload)
        return self.commitment()

    @staticmethod
    def _varuint(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)

    def write_pending_ots(self, uri="https://alice.btc.calendar.opentimestamps.org"):
        u = uri.encode()
        self.write_ots(b"\xf0\x10" + NONCE + b"\x08" + b"\x00" + vp.TAG_PENDING + bytes([len(u) + 1, len(u)]) + u)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.c = CardFolder(self.tmp, created="2025-11-19T21:30:00Z")
        self.when = 1763595667  # 2025-11-19 23:41:07 UTC
        self.created = "2025-11-19T21:30:00Z"

    def tearDown(self):
        self._tmp.cleanup()

    def run_file(self, rel, get=None, offline=False, sources=(A, B)):
        return vp.verify_file(self.c.clip(rel), offline=offline, sources=list(sources), get=get or explorer({}), pow_limit=REGTEST_LIMIT)

    def last(self, v):
        self.assertTrue(v.lines[-1].startswith("RESULT:    "), v.lines[-1])
        return v.lines[-1]

    def test_ok(self):
        self.c = CardFolder(self.tmp + "/ok", created=self.created)
        get = self.anchored_for(self.c)
        v = self.run_file("CLIP/A.mov", get)
        self.assertEqual(v.outcome, "OK")
        digest = sha(self.c.files["CLIP/A.mov"]).hex()
        self.assertEqual(v.lines[0], "File:      CLIP/A.mov")
        self.assertEqual(v.lines[1], "SHA-256:   %s  — matches offload_proof.json (card A001, 2026-11-19, 3 files, Merkle root OK)" % digest)
        self.assertEqual(v.lines[2], "Anchor:    Bitcoin block 800000, 2025-11-19 23:41:07 UTC (a.example and b.example agree)")
        self.assertEqual(self.last(v), "RESULT:    OK — this file existed unchanged no later than 2025-11-19 23:41:07 UTC.")
        self.assertFalse(any("authentic" in l.lower() for l in v.lines if "not" not in l))

    def anchored_for(self, card):
        return explorer({800000: mine(card.write_complete_ots(), self.when)})

    def test_non_ascii_names(self):
        get = self.anchored_for(self.c)
        for rel in ("CLIP/\u010cesk\u00e1 \u017e.mov", "CLIP/\U0001F600.mov"):
            v = self.run_file(rel, get)
            self.assertEqual(v.outcome, "OK", v.lines)
            self.assertEqual(v.lines[0], "File:      " + rel)

    def test_one_source_warns(self):
        msg = self.c.write_complete_ots()
        get = explorer({800000: mine(msg, self.when)}, fail=["https://down.example"])
        v = self.run_file("CLIP/A.mov", get, sources=(A, "https://down.example/api"))
        self.assertEqual(v.outcome, "OK")
        self.assertIn("Warning:   only one block header source answered — the header could not be compared with a second one", v.lines)
        self.assertIn("(only a.example answered)", v.lines[2])

    def test_clock_warning(self):
        self.c = CardFolder(self.tmp + "/c", created="2025-11-25T21:30:00Z")
        v = self.run_file("CLIP/A.mov", self.anchored_for(self.c))
        self.assertEqual(v.outcome, "OK")
        w = [l for l in v.lines if l.startswith("Warning:")]
        self.assertEqual(len(w), 1)
        self.assertIn("5 days after the Bitcoin block", w[0])
        self.assertIn("the proof stays valid", w[0])

    def test_changed_clip_fails(self):
        get = self.anchored_for(self.c)
        with open(self.c.clip("CLIP/A.mov"), "r+b") as fh:
            fh.write(b"\xff")
        v = self.run_file("CLIP/A.mov", get)
        self.assertEqual(v.outcome, "FAILED")
        self.assertEqual(self.last(v), "RESULT:    FAILED — SHA-256 does not match any file of the proof.")

    def test_changed_manifest_fails_every_byte_kind(self):
        get = self.anchored_for(self.c)
        good = self.c.manifest_bytes()
        for i in (0, 10, len(good) // 2, len(good) - 1):
            bad = bytearray(good)
            bad[i] ^= 0x01
            self.c.write_manifest(bytes(bad))
            v = self.run_file("CLIP/A.mov", get)
            self.assertEqual(v.outcome, "FAILED", i)
        self.c.write_manifest(good)

    def test_edited_but_not_canonical_manifest(self):
        get = self.anchored_for(self.c)
        self.c.write_manifest(self.c.manifest_bytes().replace(b'"complete":true', b'"complete": true'))
        v = self.run_file("CLIP/A.mov", get)
        self.assertEqual(self.last(v), "RESULT:    FAILED — the manifest is not canonical — it was edited.")

    def test_wrong_root_and_count(self):
        get = self.anchored_for(self.c)
        self.c.obj["merkle"]["root"] = "sha256:" + "00" * 32
        self.c.write_manifest()
        self.assertEqual(self.last(self.run_file("CLIP/A.mov", get)),
                         "RESULT:    FAILED — the Merkle root in the manifest does not match its files.")
        good_root = vp.merkle_root(vp.ordered_leaves([(sha(d), len(d)) for d in self.c.files.values()])).hex()
        self.c.obj["merkle"]["root"] = "sha256:" + good_root
        self.c.obj["merkle"]["count"] = 4
        self.c.write_manifest()
        self.assertIn("file count in the manifest (4) does not match its files (3)", self.last(self.run_file("CLIP/A.mov", get)))

    def test_ots_of_another_digest_fails(self):
        self.c.write_complete_ots()
        self.c.write_ots(b"\x00" + vp.TAG_PENDING + b"\x02\x01a", digest=sha(b"something else"))
        v = self.run_file("CLIP/A.mov", explorer({}))
        self.assertEqual(self.last(v), "RESULT:    FAILED — the manifest changed after it was anchored (its SHA-256 is not the one "
                                       "offload_proof.json.ots was made for).")

    def test_damaged_ots_fails(self):
        self.c.write_complete_ots()
        with open(self.c.manifest + ".ots", "r+b") as fh:
            fh.seek(3)
            fh.write(b"\x99")
        v = self.run_file("CLIP/A.mov", explorer({}))
        self.assertEqual(v.outcome, "FAILED")
        self.assertIn("offload_proof.json.ots is not a valid timestamp", self.last(v))

    def test_flipped_nonce_byte_fails_against_the_block(self):
        msg = self.c.write_complete_ots()
        get = explorer({800000: mine(msg, self.when)})
        with open(self.c.manifest + ".ots", "r+b") as fh:
            data = bytearray(fh.read())
            data[len(vp.OTS_MAGIC) + 2 + 32 + 2] ^= 1  # first nonce byte
            fh.seek(0)
            fh.write(bytes(data))
        v = self.run_file("CLIP/A.mov", get)
        self.assertEqual(self.last(v), "RESULT:    FAILED — a Bitcoin attestation in the .ots does not match block 800000.")

    def test_pending_is_not_yet(self):
        self.c.write_pending_ots()
        v = self.run_file("CLIP/A.mov")
        self.assertEqual(v.outcome, "NOT YET")
        self.assertIn("Anchor:    pending at 1 calendar (alice.btc.calendar.opentimestamps.org) — not in Bitcoin yet", v.lines)
        self.assertTrue(self.last(v).startswith("RESULT:    NOT YET — the timestamp is not in Bitcoin yet"))

    def test_offline_is_not_yet_and_asks_nobody(self):
        self.c.write_complete_ots()

        def boom(url):
            raise AssertionError("offline must not ask a block explorer")
        v = self.run_file("CLIP/A.mov", boom, offline=True)
        self.assertEqual(v.outcome, "NOT YET")
        self.assertIn("Anchor:    Bitcoin block 800000 (in offload_proof.json.ots; not checked — offline)", v.lines)
        self.assertEqual(self.last(v), "RESULT:    NOT YET — the Bitcoin block was not checked (offline).")

    def test_explorers_down_or_disagreeing_is_not_yet(self):
        msg = self.c.write_complete_ots()
        v = self.run_file("CLIP/A.mov", explorer({}, fail=[A, B]))
        self.assertEqual(v.outcome, "NOT YET")
        self.assertEqual(self.last(v), "RESULT:    NOT YET — the Bitcoin block could not be checked — try again later.")
        h = mine(msg, self.when)
        v = self.run_file("CLIP/A.mov", explorer({800000: h}, lie={B: {800000: mine(sha(b"x"), self.when)}}))
        self.assertEqual(v.outcome, "NOT YET")

    def test_no_ots_yet_is_not_yet(self):
        v = self.run_file("CLIP/A.mov")
        self.assertEqual(v.outcome, "NOT YET")
        self.assertIn("Anchor:    none yet — offload_proof.json.ots is not next to the manifest", v.lines)

    def test_no_proof_folder_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.mov")
            with open(p, "wb") as fh:
                fh.write(b"x")
            v = vp.verify_file(p, offline=True)
            self.assertEqual(v.outcome, "FAILED")
            self.assertEqual(v.lines[-1], "RESULT:    FAILED — " + vp.NO_PROOF_FILE + ".")

    def test_renamed_file_is_found_by_hash(self):
        get = self.anchored_for(self.c)
        os.rename(self.c.clip("CLIP/A.mov"), self.c.clip("CLIP/renamed.mov"))
        v = self.run_file("CLIP/renamed.mov", get)
        self.assertEqual(v.outcome, "OK")
        self.assertIn("Note:      listed as CLIP/A.mov (renamed or moved)", v.lines)

    def test_folder_mode(self):
        get = self.anchored_for(self.c)
        v = vp.verify_folder(self.c.card, sources=[A, B], get=get, pow_limit=REGTEST_LIMIT)
        self.assertEqual(v.outcome, "OK")
        self.assertIn("Files:     3 files OK, 0 changed, 0 missing", v.lines)
        with open(self.c.clip("CLIP/A.mov"), "r+b") as fh:
            fh.write(b"\xff")
        v = vp.verify_folder(self.c.card, sources=[A, B], get=get, pow_limit=REGTEST_LIMIT)
        self.assertEqual(v.outcome, "FAILED")
        self.assertIn("Changed:   CLIP/A.mov", v.lines)
        self.assertEqual(v.lines[-1], "RESULT:    FAILED — 1 file changed since the proof was made.")

    def test_cli_offline_exit_codes(self):
        self.c.write_pending_ots()
        script = os.path.join(HERE, "verify_proof.py")
        r = subprocess.run([sys.executable, "-I", script, self.c.clip("CLIP/A.mov"), "--offline"], capture_output=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        out = r.stdout.decode("utf-8")
        self.assertIn("SHA-256:   " + sha(self.c.files["CLIP/A.mov"]).hex(), out)
        with open(self.c.clip("CLIP/A.mov"), "r+b") as fh:
            fh.write(b"\xff")
        r = subprocess.run([sys.executable, "-I", script, self.c.clip("CLIP/A.mov"), "--offline"], capture_output=True)
        self.assertEqual(r.returncode, 1)


class BigManifestTests(unittest.TestCase):
    def test_20000_files_parse_canonically_and_root_checks(self):
        with tempfile.TemporaryDirectory() as d:
            c = CardFolder(d, files={"CLIP/%05d \u017e\U0001F600.mov" % i: str(i).encode() for i in range(20000)}, write_clips=False)
            t = time.perf_counter()
            m = vp._load(c.manifest)
            self.assertIsNone(m.error)
            self.assertEqual(vp.jcs_bytes(m.obj), m.data)
            self.assertEqual(vp.manifest_root_hex(m.manifest.files), m.manifest.merkle_root)
            self.assertLess(time.perf_counter() - t, 5)


if __name__ == "__main__":
    unittest.main()
