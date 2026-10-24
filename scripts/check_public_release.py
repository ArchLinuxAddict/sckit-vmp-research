#!/usr/bin/env python3
"""Fail-closed public release check: files, links, data shape, sensitive strings."""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {
    ".apk", ".apks", ".dex", ".odex", ".oat", ".vdex", ".so", ".vmp",
    ".pcap", ".pcapng", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip",
    ".jar", ".class", ".der", ".jks", ".keystore", ".p12", ".pem",
}
SENSITIVE_PATTERNS = [
    "nmms" + "king-64bf4", r"firebaseio\.com", "SM-" + "S711B", "SM-" + "A176B",
    "/home/" + "furjack", r"\b(?:164\.100|35\.190|34\.120|192\.168)\.",
    r"AIza[0-9A-Za-z_-]{20,}", r"ghp_[A-Za-z0-9]{20,}",
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"\bBearer\s+[A-Za-z0-9._-]{20,}", r"\bRZ[0-9A-Z]{10,}\b",
]
REQUIRED = [
    "README.md", "DISCLAIMER.md", "CONTRIBUTING.md", "SECURITY.md",
    "docs/overview.md", "docs/methodology.md", "docs/architecture.md",
    "docs/phase-history.md", "docs/findings.md", "docs/limitations.md",
    "docs/reproduction.md", "docs/ethics-and-scope.md",
    "docs/publication-audit.md",
    "data/opcode_dispatch.csv", "data/method-record-excerpt.csv",
    "data/managed-native-crosswalk-excerpt.csv", "data/private-source-hashes.json",
    "data/public-evidence-summary.json", "data/public-files.json",
    "scripts/phase11/vmp_format.py", "scripts/phase11/analyze_native_opcodes.py",
    "examples/minimal-vmp/minimal.dat",
]


def slug(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    text = re.sub(r"\s+", "-", text)
    return text.strip("-")


def anchors(path: Path) -> set[str]:
    out = set()
    fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
        if m:
            out.add(slug(m.group(1)))
    return out


def main() -> int:
    problems: list[str] = []
    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            problems.append(f"missing required file: {rel}")

    text_files = []
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT)
        if ".git" in rel.parts:
            continue
        if p.suffix.lower() in FORBIDDEN_SUFFIXES:
            problems.append(f"forbidden artifact suffix: {rel}")
        if p.stat().st_size > 2_000_000:
            problems.append(f"oversized public file: {rel} ({p.stat().st_size} bytes)")
        if p.suffix.lower() in {".md", ".txt", ".json", ".csv", ".py", ".gitignore"}:
            text_files.append(p)

    for p in text_files:
        rel = p.relative_to(ROOT)
        try:
            text = p.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            problems.append(f"non-UTF8 public text: {rel}")
            continue
        for pat in SENSITIVE_PATTERNS:
            if re.search(pat, text, re.I):
                problems.append(f"sensitive-pattern {pat!r} in {rel}")

    # Markdown links/anchors.
    for p in ROOT.rglob("*.md"):
        text = p.read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)]+)\)", text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            file_part, _, anchor = target.partition("#")
            dest = (p.parent / file_part).resolve() if file_part else p.resolve()
            try:
                dest.relative_to(ROOT.resolve())
            except ValueError:
                problems.append(f"link escapes root: {p.relative_to(ROOT)} -> {target}")
                continue
            if not dest.exists():
                problems.append(f"broken link: {p.relative_to(ROOT)} -> {target}")
                continue
            if anchor and dest.suffix.lower() == ".md" and anchor not in anchors(dest):
                problems.append(f"broken anchor: {p.relative_to(ROOT)} -> {target}")

    try:
        json.loads((ROOT / "data/private-source-hashes.json").read_text(encoding="utf-8"))
        json.loads((ROOT / "data/public-evidence-summary.json").read_text(encoding="utf-8"))
    except Exception as exc:
        problems.append(f"invalid JSON data: {exc}")

    with (ROOT / "data/opcode_dispatch.csv").open(newline="", encoding="utf-8") as fh:
        opcodes = list(csv.DictReader(fh))
    if len(opcodes) != 159 or len({r["handler_elf_va"] for r in opcodes}) != 116:
        problems.append("opcode_dispatch.csv shape mismatch (expected 159 rows / 116 handlers)")

    if problems:
        print("PUBLIC RELEASE CHECK FAILED")
        for p in problems:
            print(" -", p)
        return 1
    print(f"PUBLIC RELEASE CHECK PASSED: {len(text_files)} text files, links/anchors, data schemas, no forbidden artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
