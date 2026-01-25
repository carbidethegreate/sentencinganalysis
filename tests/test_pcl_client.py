import json
import unittest

from pacer_http import PacerHttpResponse
from pcl_client import PclClient


class DummyHttpClient:
    def __init__(self) -> None:
        self.calls = []

    def request(
        self,
        method,
        url,
        *,
        headers=None,
        data=None,
        timeout=30,
        include_cookie=False,
        _retried=False,
    ):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "data": data,
            }
        )
        return PacerHttpResponse(status_code=200, headers={}, body=b"{}")


class PclClientTests(unittest.TestCase):
    def test_case_search_strips_paging_fields(self):
        http_client = DummyHttpClient()
        client = PclClient(http_client, "https://qa-pcl.uscourts.gov/pcl-public-api/rest")
        payload = {
            "courtId": ["akdc"],
            "dateFiledFrom": "2024-01-01",
            "dateFiledTo": "2024-01-31",
            "pageSize": 54,
            "page_size": 54,
            "page": 2,
        }

        client.immediate_case_search(0, payload)

        self.assertTrue(http_client.calls)
        sent = json.loads(http_client.calls[0]["data"].decode("utf-8"))
        self.assertNotIn("pageSize", sent)
        self.assertNotIn("page_size", sent)
        self.assertNotIn("page", sent)


if __name__ == "__main__":
    unittest.main()
