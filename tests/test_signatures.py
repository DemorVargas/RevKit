"""Signature rules."""

from __future__ import annotations

import unittest

from revkit import signatures

import helpers


class ScanTests(unittest.TestCase):
    def test_finds_url(self):
        hits = signatures.scan(b"see http://evil.example.invalid/a for details", signatures.default_rules())
        self.assertTrue(any(h.rule == "network_url" for h in hits))

    def test_finds_powershell(self):
        hits = signatures.scan(b"powershell.exe -enc AAAA", signatures.default_rules())
        self.assertTrue(any(h.rule == "powershell" for h in hits))

    def test_finds_registry_persistence(self):
        data = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        hits = signatures.scan(data, signatures.default_rules())
        self.assertTrue(any(h.rule == "registry_run" for h in hits))

    def test_finds_needle(self):
        hits = signatures.scan(b"\x00VirtualAllocEx\x00", signatures.default_rules())
        self.assertTrue(any(h.rule == "process_injection" for h in hits))

    def test_no_hits_on_clean_data(self):
        hits = signatures.scan(b"just a harmless sentence with no indicators at all", signatures.default_rules())
        self.assertEqual(hits, [])

    def test_hits_carry_offsets(self):
        data = b"xx http://a.invalid/ yy http://b.invalid/"
        hits = [h for h in signatures.scan(data, signatures.default_rules()) if h.rule == "network_url"]
        self.assertEqual(hits[0].offset, 3)

    def test_max_hits_is_respected(self):
        data = b"http://a.invalid/ " * 200
        hits = signatures.scan(data, signatures.default_rules(), max_hits=5)
        self.assertEqual(len(hits), 5)

    def test_bad_pattern_raises(self):
        rule = signatures.Rule(name="broken", patterns=["[unclosed"])
        with self.assertRaises(Exception):
            signatures.scan(b"data", [rule])


class SeverityTests(unittest.TestCase):
    def test_count_by_severity(self):
        data = b"http://a.invalid/ powershell.exe -enc AAAA \x00VirtualAllocEx\x00"
        hits = signatures.scan(data, signatures.default_rules())
        counts = signatures.count_by_severity(hits)
        self.assertGreater(counts["high"], 0)
        self.assertGreater(counts["info"], 0)

    def test_highest_severity(self):
        hits = signatures.scan(b"powershell.exe -enc AAAA", signatures.default_rules())
        self.assertEqual(signatures.highest_severity(hits), "high")

    def test_highest_severity_with_no_hits(self):
        self.assertEqual(signatures.highest_severity([]), "info")

    def test_hits_sorted_most_severe_first(self):
        data = b"http://a.invalid/ \x00VirtualAllocEx\x00"
        hits = signatures.scan(data, signatures.default_rules())
        order = [signatures.SEVERITY_ORDER[h.severity] for h in hits]
        self.assertEqual(order, sorted(order, reverse=True))


class RuleTests(unittest.TestCase):
    def test_custom_rule(self):
        rule = signatures.Rule(name="my_rule", patterns=[r"needle\d+"], severity="low")
        hits = signatures.scan(b"a needle42 b", [rule])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].rule, "my_rule")
        self.assertEqual(hits[0].matched, b"needle42")

    def test_custom_needle(self):
        rule = signatures.Rule(name="bytes", needles=[b"\xde\xad\xbe\xef"], severity="critical")
        hits = signatures.scan(b"\x00\xde\xad\xbe\xef\x00", [rule])
        self.assertEqual(hits[0].severity, "critical")

    def test_default_rules_returns_copies(self):
        a = signatures.default_rules()
        b = signatures.default_rules()
        a[0].name = "changed"
        self.assertNotEqual(b[0].name, "changed")

    def test_rule_to_dict_roundtrips_fields(self):
        rule = signatures.Rule(name="r", patterns=["x"], needles=[b"y"], tags=["t"], severity="low")
        d = rule.to_dict()
        self.assertEqual(d["needles"], ["79"])
        self.assertEqual(d["tags"], ["t"])
        self.assertEqual(d["severity"], "low")

    def test_hit_to_dict_includes_text(self):
        hit = signatures.Hit(rule="r", description="d", severity="low", offset=0, matched=b"hello")
        self.assertEqual(hit.to_dict()["matched_text"], "hello")


if __name__ == "__main__":
    unittest.main()
