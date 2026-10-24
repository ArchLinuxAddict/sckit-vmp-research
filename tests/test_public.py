import csv
import re
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "phase11"))
import vmp_format as v  # noqa: E402


class SyntheticContainerTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / "examples" / "minimal-vmp" / "minimal.dat"
        self.data = self.path.read_bytes()

    def test_synthetic_container_parses(self):
        vmp = v.parse_bytes(self.data, self.path)
        self.assertEqual(vmp.sha256, "53b3638961ef5ea2c9036f286d2e41d438558212b1990a46494791226897336f")
        self.assertEqual([s.offset for s in vmp.sections], [64, 67, 71, 75, 87, 107])
        self.assertEqual([s.count for s in vmp.sections], [1, 1, 1, 1, 1, 1])
        self.assertEqual(vmp.string_count, 1)
        self.assertEqual(vmp.decrypt_string(0), "X")
        self.assertEqual(vmp.method_count, 1)
        self.assertEqual(vmp.method(0).class_name, "X")
        self.assertEqual(vmp.method(0).method_name, "X")
        self.assertEqual(vmp.code_start, 64)
        self.assertEqual(vmp.code_end, 64)

    def test_bad_magic_rejected(self):
        with self.assertRaisesRegex(v.VmpFormatError, "bad magic"):
            v.parse_bytes(b"X" + self.data[1:], "<test>")

    def test_truncated_rejected(self):
        for cut in (32, 64, 100, len(self.data) - 1):
            with self.subTest(cut=cut), self.assertRaises(v.VmpFormatError):
                v.parse_bytes(self.data[:cut], "<test>")

    def test_nonmonotonic_offsets_rejected(self):
        data = bytearray(self.data)
        struct.pack_into("<I", data, 16, 63)
        with self.assertRaises(v.VmpFormatError):
            v.parse_bytes(bytes(data), "<test>")

    def test_xor_and_mutf8_primitives(self):
        self.assertEqual(v.decode_string_bytes(b"Lkcua"), b"Ljava")
        self.assertEqual(v.decode_modified_utf8(b"\xc0\x80"), "\x00")
        self.assertEqual(v.decode_modified_utf8("é".encode("utf-8")), "é")
        self.assertEqual(v.utf16_unit_count("😀"), 2)


class PublicDataTests(unittest.TestCase):
    def test_opcode_table_shape(self):
        with (ROOT / "data" / "opcode_dispatch.csv").open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 159)
        self.assertEqual(len({r["handler_elf_va"] for r in rows}), 116)
        self.assertEqual(rows[0]["opcode"], "1")
        self.assertEqual(rows[-1]["opcode"], "159")
        self.assertEqual(rows[49]["handler_elf_va"], rows[55]["handler_elf_va"])

    def test_method_excerpt(self):
        with (ROOT / "data" / "method-record-excerpt.csv").open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        by_id = {int(r["method_id"]): r for r in rows}
        self.assertEqual(by_id[1839]["method_name"], "run")
        self.assertEqual(by_id[1744]["method_name"], "fetch")
        self.assertEqual(by_id[1641]["method_name"], "hasNet")
        self.assertEqual(by_id[1839]["code_record_id"], "1839")
        self.assertEqual(by_id[1744]["class_descriptor"], "Lop/jat/dilog/LoginDialog$NetTask;")

    def test_crosswalk_excerpt(self):
        with (ROOT / "data" / "managed-native-crosswalk-excerpt.csv").open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        ids = {int(r["invocation_id"]) for r in rows}
        self.assertIn(1839, ids)
        self.assertIn(1744, ids)
        self.assertTrue(all("method[" in r["candidate_vmp_record_or_opcode"] for r in rows))

    def test_public_evidence_summary(self):
        import json
        summary = json.loads((ROOT / "data" / "public-evidence-summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["phase"], 11)
        self.assertEqual(summary["vmp"]["method_records"], 1845)
        self.assertEqual(summary["vmp"]["code_records"], 724)
        self.assertEqual(summary["dispatch"]["opcodes"], 159)
        self.assertEqual(summary["dispatch"]["unique_handlers"], 116)
        self.assertIn("private", summary["redistribution"].lower())


class ReleasePolicyTests(unittest.TestCase):
    forbidden_suffixes = {".apk", ".dex", ".so", ".vmp", ".pcap", ".pcapng", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip", ".jar", ".class"}
    forbidden_patterns = [
        "nmms" + "king-64bf4", r"firebaseio\.com", "SM-" + "S711B", "SM-" + "A176B",
        "/home/" + "furjack", r"\b(?:164\.100|35\.190|34\.120|192\.168)\.",
        r"AIza[0-9A-Za-z_-]{20,}", r"ghp_[A-Za-z0-9]{20,}",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"\bBearer\s+[A-Za-z0-9._-]{20,}",
    ]

    def test_no_forbidden_binary_extensions(self):
        bad = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file() and p.suffix.lower() in self.forbidden_suffixes]
        # The synthetic example uses .dat, not .vmp, and no image/binary captures are allowed.
        self.assertEqual(bad, [])

    def test_no_known_sensitive_patterns(self):
        hits = []
        for p in ROOT.rglob("*.md"):
            text = p.read_text(encoding="utf-8", errors="replace")
            for pat in self.forbidden_patterns:
                if re.search(pat, text, re.I):
                    hits.append((str(p.relative_to(ROOT)), pat))
        self.assertEqual(hits, [])

    def test_no_large_unreviewed_files(self):
        # Public tree is documentation/data/scripts; fail closed on oversized files.
        bad = [(str(p.relative_to(ROOT)), p.stat().st_size) for p in ROOT.rglob("*") if p.is_file() and p.stat().st_size > 2_000_000]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
