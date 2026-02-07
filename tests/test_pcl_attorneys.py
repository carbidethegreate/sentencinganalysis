import unittest
from datetime import date

from sqlalchemy import MetaData, create_engine

from pcl_models import build_pcl_tables
from pcl_queries import list_attorneys


class PclAttorneyListTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", future=True)
        metadata = MetaData()
        self.tables = build_pcl_tables(metadata)
        metadata.create_all(self.engine)
        self._seed()

    def _seed(self):
        cases = self.tables["pcl_cases"]
        case_fields = self.tables["pcl_case_fields"]
        with self.engine.begin() as conn:
            conn.execute(
                cases.insert(),
                [
                    {
                        "court_id": "vidc",
                        "case_number": "3:24-cr-00019",
                        "case_number_full": "3:24-cr-00019-MAK",
                        "case_type": "cr",
                        "date_filed": date(2024, 9, 3),
                        "short_title": "USA v. Whitaker",
                        "case_title": "United States v. Whitaker",
                        "data_json": "{}",
                    },
                    {
                        "court_id": "vidc",
                        "case_number": "3:25-mj-00099",
                        "case_number_full": "3:25-mj-00099",
                        "case_type": "mj",
                        "date_filed": date(2025, 11, 1),
                        "short_title": "USA v. Roe",
                        "case_title": "United States v. Roe",
                        "data_json": "{}",
                    },
                ],
            )
            case_rows = conn.execute(cases.select().order_by(cases.c.id.asc())).mappings().all()
            case_1_id = int(case_rows[0]["id"])
            case_2_id = int(case_rows[1]["id"])

            conn.execute(
                case_fields.insert(),
                [
                    {
                        "case_id": case_1_id,
                        "field_name": "docket_attorneys",
                        "field_value_json": [
                            {
                                "name": "Jane Lawyer",
                                "organization": "Law Firm A",
                                "emails": ["jane@example.com"],
                                "phones": ["555-100-2000"],
                                "websites": ["https://lawfirma.example.com"],
                                "designations": ["Retained"],
                                "party_name": "David Whitaker",
                                "party_type": "Defendant",
                            },
                            {
                                "name": "John Prosecutor",
                                "emails": ["john.prosecutor@usdoj.gov"],
                                "party_name": "USA",
                                "party_type": "Plaintiff",
                            },
                        ],
                    },
                    {
                        "case_id": case_2_id,
                        "field_name": "docket_attorneys",
                        "field_value_json": [
                            {
                                "name": "Jane Lawyer",
                                "organization": "Law Firm A",
                                "emails": ["jane@example.com"],
                                "phones": ["(555) 100-2000"],
                                "faxes": ["555-111-2222"],
                                "party_name": "Alice Roe",
                                "party_type": "Defendant",
                            }
                        ],
                    },
                ],
            )

    def test_list_attorneys_aggregates_related_cases(self):
        result = list_attorneys(self.engine, self.tables, page=1, page_size=25)
        self.assertEqual(result.pagination.total, 2)
        self.assertEqual(len(result.rows), 2)

        jane = next(row for row in result.rows if row["name"] == "Jane Lawyer")
        self.assertEqual(jane["case_count"], 2)
        self.assertEqual(jane["emails"], ["jane@example.com"])
        self.assertIn("555-100-2000", jane["phones"])
        self.assertIn("(555) 100-2000", jane["phones"])
        self.assertEqual(jane["faxes"], ["555-111-2222"])
        self.assertEqual(jane["organizations"], ["Law Firm A"])
        self.assertEqual(
            {case["case_number"] for case in jane["related_cases"]},
            {"3:24-cr-00019", "3:25-mj-00099"},
        )

    def test_list_attorneys_searches_contact_fields(self):
        result = list_attorneys(
            self.engine,
            self.tables,
            search_text="usdoj.gov",
            page=1,
            page_size=25,
        )
        self.assertEqual(result.pagination.total, 1)
        self.assertEqual(result.rows[0]["name"], "John Prosecutor")


if __name__ == "__main__":
    unittest.main()
