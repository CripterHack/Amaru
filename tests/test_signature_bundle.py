"""Cross-engine checks for the signatures shipped by Amaru."""

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

import yara
import yara_x

from scripts.scan_yarax import SIGNATURES, compile_rules, rule_files


ROOT = SIGNATURES.parent
SCANNER = ROOT / "scripts" / "scan_yarax.py"


class SignatureBundleTests(unittest.TestCase):
    def test_engines_compile_the_same_rule_catalog(self):
        paths = rule_files(SIGNATURES)
        source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        classic = yara.compile(source=source)
        classic_names = {rule.identifier for rule in classic}
        self.assertIn("EICAR_Test_File", classic_names)
        self.assertEqual(classic_names, {rule.identifier for rule in compile_rules(paths)})

    def test_installer_contains_the_tested_sources(self):
        packaged = ROOT / "installer" / "signatures"
        sources = {p.relative_to(SIGNATURES): p for p in rule_files(SIGNATURES)}
        copies = {p.relative_to(packaged): p for p in packaged.rglob("*.yar")}
        self.assertEqual(sources.keys(), copies.keys())
        for name, source in sources.items():
            with self.subTest(rule_file=name):
                self.assertEqual(source.read_bytes(), copies[name].read_bytes())

    def test_invalid_rules_stop_compilation(self):
        with TemporaryDirectory() as tmp:
            invalid = Path(tmp) / "invalid.yar"
            invalid.write_text("rule invalid { condition: }", encoding="utf-8")
            with self.assertRaises(yara_x.CompileError):
                compile_rules([SIGNATURES / "official" / "eicar_test.yar", invalid])

    def test_cli_reports_clean_match_and_error(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "fixture"
            for data, expected in [(b"benign text", []), (b".locked", ["RansomwareIndicators"])]:
                with self.subTest(data=data):
                    target.write_bytes(data)
                    run = subprocess.run([sys.executable, SCANNER, target], capture_output=True)
                    self.assertEqual(run.returncode, int(bool(expected)), run.stderr)
                    self.assertEqual(json.loads(run.stdout), expected)
            target.unlink()
            run = subprocess.run([sys.executable, SCANNER, target], capture_output=True)
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertTrue(run.stderr)
            self.assertEqual(run.stdout, b"")


if __name__ == "__main__":
    unittest.main()
