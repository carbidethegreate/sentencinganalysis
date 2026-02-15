import unittest

from pcl_queries import _aggregate_attorneys


class AttorneyAggregationTests(unittest.TestCase):
    def test_merges_same_name_buckets_when_they_share_a_case(self):
        # Same attorney appears twice in the same case: one row has contact info and
        # one row is name-only. Without consolidation this can produce duplicate cards.
        source_rows = [
            {
                "case_id": 123,
                "court_id": "paedc",
                "case_type": "cr",
                "case_number": "1",
                "case_number_full": "2:2026cr00001",
                "short_title": "USA v. DOE",
                "case_title": "USA v. DOE - JOHN DOE",
                "date_filed": None,
                "updated_at": None,
                "field_value_json": [
                    {
                        "name": "Adam Francis Sleeper",
                        "organization": "United States Attorney's Office",
                        "emails": ["adam.sleeper@usdoj.gov"],
                        "phones": ["340-774-5757"],
                        "designations": ["US Attorney/Assistant U.S.Attorney"],
                        "roles": ["LEAD ATTORNEY"],
                    },
                    {"name": "Adam Francis Sleeper"},
                ],
            }
        ]

        rows = _aggregate_attorneys(source_rows, search_text="")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "Adam Francis Sleeper")
        self.assertIn("adam.sleeper@usdoj.gov", rows[0]["emails"])
        self.assertTrue(rows[0]["case_count"] >= 1)

    def test_does_not_merge_same_name_buckets_without_contact_overlap_or_case_overlap(self):
        # Two different cases, same name, but identity keys differ (email vs phone).
        # With no case overlap, we keep separate buckets to avoid merging different people.
        source_rows = [
            {
                "case_id": 1,
                "court_id": "paedc",
                "case_type": "cr",
                "case_number": "1",
                "case_number_full": "2:2026cr00001",
                "short_title": "Case A",
                "case_title": "Case A",
                "date_filed": None,
                "updated_at": None,
                "field_value_json": [{"name": "Jane Smith", "emails": ["jane.smith@example.com"]}],
            },
            {
                "case_id": 2,
                "court_id": "paedc",
                "case_type": "cr",
                "case_number": "2",
                "case_number_full": "2:2026cr00002",
                "short_title": "Case B",
                "case_title": "Case B",
                "date_filed": None,
                "updated_at": None,
                "field_value_json": [{"name": "Jane Smith", "phones": ["212-555-1111"]}],
            },
        ]

        rows = _aggregate_attorneys(source_rows, search_text="")
        self.assertEqual(len(rows), 2)
        names = sorted([row["name"] for row in rows])
        self.assertEqual(names, ["Jane Smith", "Jane Smith"])


if __name__ == "__main__":
    unittest.main()
