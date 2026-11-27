"""Validate Amaru's EICAR rule against the pinned NDAAL plain-byte corpus."""

import hashlib
import unittest
from pathlib import Path

import yara
import yara_x


ROOT = Path(__file__).resolve().parents[1]
RULE = ROOT / "signatures" / "official" / "eicar_test.yar"
EICAR_RULE_NAME = "EICAR_Test_File"

# Each ID identifies an entire directory in NDAAL revision b1ba5e955314d7e673844c1366d9d2cf9b7e1180.
# The five directories contain 129 distinct suffix lengths each.
SUFFIX_TREES = (
    ("CR", b"\r", "0721da248043c743bd3c05d1e63e7d1e7f6c9490"),
    ("LF", b"\n", "ea95482d5d96fd0c618467b0e6355256e026b3aa"),
    ("CTRL-Z", b"\x1a", "a4ac65dad1dffc40efcbf031238d2e920451d6c3"),
    ("space", b" ", "e82397aaaeca50a13480ef1576131bea1b048d56"),
    ("tab", b"\t", "210ace695676724befa040b42f01feb4168b2bf5"),
)

POSITION_DIR = "EICAR_position_variations/"
# Paths are relative to the upstream dataset/ directory. Hashes cover actual upstream bytes.
PLAIN_FILES = (
    ("eicar.com", b"", b"", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
    ("eicar.txt", b"", b"\n", "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"),
    (POSITION_DIR + "eicar_at_the_end_spaces.txt", b" " * 5, b"",
     "b0ea5b694ff1169dcb49f5696dcf57aa950d52dd69b82e940ca5ddc08311865d"),
    (POSITION_DIR + "eicar_at_the_end_underscore.txt", b"_" * 5, b"",
     "e7a205d1792d89f231ab938da99e1b54a2c4831285a152a4f552304c5bdd0fea"),
    (POSITION_DIR + "eicar_in_the_middle_spaces.txt", b" " * 5, b" " * 5,
     "9d19eb7d3c08b2a335d585b4e94e8b1ab395f44aba2eefbb4d60ec1b7dff61b3"),
    (POSITION_DIR + "eicar_in_the_middle_underscore.txt", b"_" * 5, b"_" * 5,
     "84a7e850df24ce6c38d8b8f6c603133a45b04f736e1b9fbca022bcd3824cf435"),
)


def git_object_id(kind, data):
    header = f"{kind} {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).digest()


class EicarCorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.eicar = (ROOT / "test-eicar.txt").read_bytes()
        source = RULE.read_text(encoding="utf-8")
        cls.classic_rules = yara.compile(source=source)
        cls.x_scanner = yara_x.Scanner(yara_x.compile(source))

    def check_detection(self, sample, expected_names):
        with self.subTest(engine="YARA"):
            self.assertEqual({m.rule for m in self.classic_rules.match(data=sample)}, expected_names)
        with self.subTest(engine="YARA-X"):
            matches = self.x_scanner.scan(sample).matching_rules
            self.assertEqual({m.identifier for m in matches}, expected_names)

    def test_plain_files(self):
        for path, prefix, suffix, expected_digest in PLAIN_FILES:
            with self.subTest(path=path):
                sample = prefix + self.eicar + suffix
                self.assertEqual(hashlib.sha256(sample).hexdigest(), expected_digest)
                self.check_detection(sample, {EICAR_RULE_NAME})

    def test_trailing_character_series(self):
        for label, suffix, expected_tree in SUFFIX_TREES:
            entries = []
            for length in range(1, 130):
                name = f"EICAR_testfile_{label}_{length}_permutation.txt"
                sample = self.eicar + suffix * length
                with self.subTest(path=name):
                    self.check_detection(sample, {EICAR_RULE_NAME})
                # Serialize Git's tree entry (mode, name and raw blob object ID).
                entries.append(b"100644 " + name.encode("ascii") + b"\0" + git_object_id("blob", sample))
            with self.subTest(upstream_directory=label):
                tree = b"".join(sorted(entries))
                self.assertEqual(git_object_id("tree", tree).hex(), expected_tree)

    def test_negative_controls(self):
        for sample in (b"", b"Amaru scanner control", self.eicar[:-1]):
            with self.subTest(sample=sample):
                self.check_detection(sample, set())


if __name__ == "__main__":
    unittest.main()
