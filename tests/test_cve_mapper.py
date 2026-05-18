import unittest

from oracle_cve_intel.cve_mapper import _cpe_match_applies, _node_matches


class VersionRangeTests(unittest.TestCase):
    def test_inclusive_start_exclusive_end(self):
        match = {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "12.2.1.0",
            "versionEndExcluding": "12.2.1.5",
        }
        self.assertEqual(
            _cpe_match_applies(match, "cpe:2.3:a:oracle:weblogic_server", "12.2.1.4"),
            (True, False),
        )

    def test_exclusive_boundary(self):
        match = {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
            "versionStartExcluding": "12.2.1.4",
        }
        self.assertEqual(
            _cpe_match_applies(match, "cpe:2.3:a:oracle:weblogic_server", "12.2.1.4"),
            (False, False),
        )

    def test_vulnerable_false_never_matches(self):
        match = {
            "vulnerable": False,
            "criteria": "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "12.2.1.0",
        }
        self.assertEqual(
            _cpe_match_applies(match, "cpe:2.3:a:oracle:weblogic_server", "12.2.1.4"),
            (False, False),
        )

    def test_unparseable_version_is_ambiguous(self):
        match = {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
            "versionEndIncluding": "19.20",
        }
        self.assertEqual(
            _cpe_match_applies(match, "cpe:2.3:a:oracle:database_server", "patched to Jan 2024 CPU"),
            (None, True),
        )

    def test_and_node_requires_all_conditions(self):
        node = {
            "operator": "AND",
            "cpeMatch": [
                {
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "12.2.1.0",
                    "versionEndExcluding": "12.2.1.5",
                },
                {
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:oracle:weblogic_server:12.2.1.4:*:*:*:*:*:*:*",
                },
            ],
        }
        self.assertEqual(_node_matches(node, "cpe:2.3:a:oracle:weblogic_server", "12.2.1.4"), (True, False))


if __name__ == "__main__":
    unittest.main()
