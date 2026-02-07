import unittest

from docket_enrichment import (
    _extract_docket_entries_from_html,
    _extract_docket_header_fields_from_html,
    _strip_html,
)


SAMPLE_DOCKET_HTML = """
<html>
  <body>
    <div id="cmecfMainContent">
      <h3 align="center">
        District Court of the Virgin Islands<br>
        CRIMINAL DOCKET FOR CASE #: 3:24-cr-00019-MAK-EAH-1
      </h3>
      <table width="100%" border="0" cellspacing="5">
        <tr>
          <td valign="top"><br><b><u>Defendant                                 (1)</u></b></td>
        </tr>
        <tr>
          <td valign="top" width="40%"><b>David Whitaker</b></td>
          <td valign="top" width="20%" align="right">represented&nbsp;by</td>
          <td valign="top" width="40%">
            <b>David                J.              Cattie</b><br>
            The Cattie Law Firm, P.C.<br>
            1710 Kongens Gade<br>
            St. Thomas, VI 00802-4701<br>
            340-775-1200<br>
            Fax: 800-878-5237<br>
            Email: david.cattie&#064;cattie-law.com<br>
            <i>LEAD ATTORNEY</i><br>
            <i>ATTORNEY TO BE NOTICED</i><br>
            <i>Designation: Retained</i>
          </td>
        </tr>
        <tr>
          <td valign="top" width="40%"><br><b><u>Pending Counts</u></b></td>
          <td></td>
          <td valign="top" width="40%"><br><b><u>Disposition</u></b></td>
        </tr>
        <tr>
          <td width="40%"> FRAUD BY WIRE<br>(1-2)</td>
          <td></td>
          <td width="60%"></td>
        </tr>
        <tr>
          <td width="40%"> BRIBERY INVOLVING FEDERAL PROGRAMS<br>(3)</td>
          <td></td>
          <td width="60%">Open</td>
        </tr>
        <tr>
          <td valign="top" width="40%"><br><b><u>Highest Offense Level (Opening)</u></b></td>
        </tr>
        <tr>
          <td valign="top" width="40%">Felony</td>
        </tr>
        <tr>
          <td valign="top" width="40%"><br><b><u>Terminated Counts</u></b></td>
          <td></td>
          <td valign="top" width="40%"><br><b><u>Disposition</u></b></td>
        </tr>
        <tr>
          <td valign="top" width="40%">None</td>
        </tr>
        <tr>
          <td valign="top" width="40%"><br><b><u>Highest Offense Level (Terminated)</u></b></td>
        </tr>
        <tr>
          <td valign="top" width="40%">None</td>
        </tr>
        <tr>
          <td valign="top" width="40%"><br><b><u>Complaints</u></b></td>
          <td></td>
          <td valign="top" width="40%"><br><b><u>Disposition</u></b></td>
        </tr>
        <tr>
          <td valign="top" width="40%">None</td>
        </tr>
      </table>
      <hr>
      <table width="100%" border="0" cellspacing="5">
        <tr>
          <td valign="top" width="40%"><br><b><u>Plaintiff</u></b></td>
        </tr>
        <tr>
          <td valign="top" width="40%"><b>USA</b></td>
          <td valign="top" width="20%" align="right">represented&nbsp;by</td>
          <td valign="top" width="40%">
            <b>Alexandre            Mikhail         Dempsey</b><br>
            DOJ-Crm<br>
            1301 New York Ave NW<br>
            202-957-3014<br>
            Email: alexandre.dempsey&#064;usdoj.gov<br>
            <i>LEAD ATTORNEY</i><br>
            <i>ATTORNEY TO BE NOTICED</i><br>
            <i>Designation: US Attorney/Assistant U.S.Attorney</i><br><br>
            <b>Michael              Conley</b><br>
            U.S. Attorney&#039;s Office<br>
            5500 Veteran&#039;s Drive<br>
            Suite 260<br>
            St.Thomas, VI 00802<br>
            340-473-9060<br>
            Fax: 340-776-3474<br>
            Email: michael.conley&#064;usdoj.gov<br>
            <i>LEAD ATTORNEY</i><br>
            <i>ATTORNEY TO BE NOTICED</i>
          </td>
        </tr>
      </table>
      <table align="center" width="99%" border="1" rules="all" cellpadding="5" cellspacing="0">
        <tr><td>Date Filed</td><th>#</th><td>Docket Text</td></tr>
      </table>
    </div>
  </body>
</html>
"""


class DocketPartyParserTests(unittest.TestCase):
    def test_strip_html_handles_blank_fragment_without_exception(self):
        self.assertEqual(_strip_html("   \n\t  "), "")

    def test_extract_docket_entries_handles_blank_fragment_without_exception(self):
        self.assertEqual(_extract_docket_entries_from_html(""), [])

    def test_extracts_parties_counsel_counts_and_dispositions(self):
        fields = _extract_docket_header_fields_from_html(SAMPLE_DOCKET_HTML)
        parties = fields.get("parties") or []
        self.assertEqual(len(parties), 2)
        self.assertEqual(fields.get("party_count"), 2)
        self.assertEqual(fields.get("attorney_count"), 3)

        defendant = parties[0]
        self.assertEqual(defendant.get("party_type"), "Defendant")
        self.assertEqual(defendant.get("party_index"), 1)
        self.assertEqual(defendant.get("name"), "David Whitaker")
        self.assertEqual(defendant.get("highest_offense_level_opening"), "Felony")
        self.assertEqual(defendant.get("highest_offense_level_terminated"), "None")

        pending_counts = defendant.get("pending_counts") or []
        self.assertEqual(len(pending_counts), 2)
        self.assertIn("FRAUD BY WIRE", pending_counts[0].get("count", ""))
        self.assertEqual(pending_counts[1].get("disposition"), "Open")

        terminated_counts = defendant.get("terminated_counts") or []
        self.assertEqual(len(terminated_counts), 1)
        self.assertEqual(terminated_counts[0].get("count"), "None")

        complaints = defendant.get("complaints") or []
        self.assertEqual(len(complaints), 1)
        self.assertEqual(complaints[0].get("count"), "None")

        defendant_counsel = defendant.get("represented_by") or []
        self.assertEqual(len(defendant_counsel), 1)
        self.assertEqual(defendant_counsel[0].get("name"), "David J. Cattie")
        self.assertEqual(
            defendant_counsel[0].get("designations"),
            ["Retained"],
        )
        self.assertIn("david.cattie@cattie-law.com", defendant_counsel[0].get("emails", []))

        plaintiff = parties[1]
        self.assertEqual(plaintiff.get("party_type"), "Plaintiff")
        self.assertEqual(plaintiff.get("name"), "USA")
        plaintiff_counsel_names = [item.get("name") for item in (plaintiff.get("represented_by") or [])]
        self.assertEqual(
            plaintiff_counsel_names,
            ["Alexandre Mikhail Dempsey", "Michael Conley"],
        )

    def test_extracts_non_bold_attorney_blocks_and_labeled_contacts(self):
        html = """
        <html>
          <body>
            <table>
              <tr><td><b><u>Defendant</u></b></td></tr>
              <tr>
                <td><b>John Doe</b></td>
                <td>represented&nbsp;by</td>
                <td>
                  <b>Jane Smith</b><br>
                  Law Offices of Jane Smith<br>
                  Phone 212-555-1111<br>
                  Fax 212-555-9999<br>
                  Email jane.smith@example.com<br>
                  Website: https://janesmith.example.com<br><br>
                  Alex Prosecutor<br>
                  U.S. Attorney's Office<br>
                  (340) 555-3333<br>
                  alex.prosecutor@usdoj.gov
                </td>
              </tr>
              <tr>
                <td>Date Filed</td><th>#</th><td>Docket Text</td>
              </tr>
            </table>
          </body>
        </html>
        """
        fields = _extract_docket_header_fields_from_html(html)
        parties = fields.get("parties") or []
        self.assertEqual(len(parties), 1)
        represented_by = parties[0].get("represented_by") or []
        self.assertEqual([item.get("name") for item in represented_by], ["Jane Smith", "Alex Prosecutor"])

        jane = represented_by[0]
        self.assertIn("jane.smith@example.com", jane.get("emails") or [])
        self.assertIn("212-555-1111", jane.get("phones") or [])
        self.assertIn("212-555-9999", jane.get("faxes") or [])
        self.assertIn("https://janesmith.example.com", jane.get("websites") or [])

        alex = represented_by[1]
        self.assertIn("alex.prosecutor@usdoj.gov", alex.get("emails") or [])
        self.assertIn("(340) 555-3333", alex.get("phones") or [])


if __name__ == "__main__":
    unittest.main()
