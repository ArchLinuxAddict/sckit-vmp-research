import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def slug(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    text = re.sub(r"\s+", "-", text)
    return text.strip("-")


def anchors(path: Path):
    out = set()
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
        if m:
            out.add(slug(m.group(1)))
    return out


class DocumentationTests(unittest.TestCase):
    def test_required_documents_exist(self):
        required = [
            "README.md", "DISCLAIMER.md", "CONTRIBUTING.md", "SECURITY.md",
            "docs/overview.md", "docs/methodology.md", "docs/architecture.md",
            "docs/phase-history.md", "docs/findings.md", "docs/limitations.md",
            "docs/reproduction.md", "docs/ethics-and-scope.md",
            "docs/publication-audit.md",
        ]
        for rel in required:
            self.assertTrue((ROOT / rel).is_file(), rel)

    def test_relative_links_and_anchors(self):
        failures = []
        for path in ROOT.rglob("*.md"):
            text = path.read_text(encoding="utf-8")
            for target in re.findall(r"\]\(([^)]+)\)", text):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                file_part, _, anchor = target.partition("#")
                if file_part:
                    dest = (path.parent / file_part).resolve()
                    try:
                        dest.relative_to(ROOT)
                    except ValueError:
                        failures.append((str(path.relative_to(ROOT)), target, "outside root"))
                        continue
                    if not dest.exists():
                        failures.append((str(path.relative_to(ROOT)), target, "missing file"))
                        continue
                else:
                    dest = path
                if anchor and dest.suffix.lower() == ".md" and dest.exists():
                    if anchor not in anchors(dest):
                        failures.append((str(path.relative_to(ROOT)), target, "missing anchor"))
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
