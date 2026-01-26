PACER / PCL Reference Notes

Scope
- Source folder: `Sample Pacer files and Pacer API Instructions`
- Focus files: `pacer_xml_apv3.1.pdf`, `PCL-API-Document_4.1.pdf`

Folder contents (quick inventory)
- `PACER Authentication API-2025_v2_0.pdf`: PACER auth/token flow.
- `PCL-API-Document_4.1.pdf`: Primary PCL API guide (immediate + batch search, criteria, receipts).
- `pacer_xml_apv3.1.pdf`: XML tags for appellate PACER docket/case/party outputs.
- `pcl-api-*.xsd`: XML schemas for cases, parties, billing, courts, query, reports, types, errors.
- `PACER_FOLDER_SUMMARY.md`: local summary notes.
- `TotpGeneration/` + zip: TOTP utilities.

PCL API (Document 4.1) highlights
- Two search modes:
  - Immediate search: returns results page-by-page (54 records per page). Limit is 100 pages.
  - Batch search: returns a single batch report for later download. Limit is up to 2,000 pages / 108,000 records.
- Core immediate endpoints:
  - `POST /pcl-public-api/rest/cases/find?page={page}`
  - `POST /pcl-public-api/rest/parties/find?page={page}`
- Core batch endpoints:
  - Start batch case search: `POST /pcl-public-api/rest/cases/batch` (party batch has its own endpoint).
  - Status for batch jobs: `GET /pcl-public-api/rest/cases/batch/status` (and party variant).
  - Download batch results: `GET /pcl-public-api/rest/cases/batch/download/{reportId}`.
  - Delete batch results: `DELETE /pcl-public-api/rest/cases/batch/{reportId}`.
- Receipts:
  - Responses include a `receipt` object with billing metadata (reportId, loginId, billablePages, searchFee, transactionDate, description, etc.).
  - `pageInfo` returns paging totals (page number, size, totalElements, totalPages).

Case search criteria (selected fields)
- `jurisdictionType` (ap, bk, cr, cv, mdl).
- `caseId` (numeric ID), `caseNumberFull`, `caseNumber`, `caseYear`, `caseOffice`, `caseType` (list).
- `courtId` (list) and region filters (Appendix A/E).
- Date ranges: `dateFiledFrom`/`dateFiledTo`, `effectiveDateClosedFrom`/`To`, `dateClosedFrom`/`To`.
- Bankruptcy-only: `federalBankruptcyChapter`, `dateDismissedFrom/To`, `dateDischargedFrom/To`.
- Civil/appellate: `natureOfSuit` (Appendix C/D).
- JPML: `jpmlNumber`.

Case number formats (accepted)
- `yy-nnnnn`, `yy-tp-nnnnn`, `yy tp nnnnn`, `yytpnnnnn`
- `o:yy-nnnnn`, `o:yy-tp-nnnnn`, `o:yy tp nnnnn`, `o:yytpnnnnn`
  - `o` = office digit, `yy` = year, `tp` = case type.

Party search criteria (selected fields)
- Minimal inputs: lastName or SSN (bankruptcy debtors), or date ranges.
- Party fields: `lastName`, `firstName`, `middleName`, `generation`, `partyType`, `role`, `exactNameMatch`.
- Party searches can include `courtCase` object with case-search criteria.

PACER XML tags (Appellate CM/ECF v3.1)
- Case tags: `caseNumber`, `shortTitle`, `dateFiled`, `dateLastDocketEntry`, `origCaseNumber`, `origCaseLink`, `dateTerminated`, `natureOfSuit`, `type`, `status`.
- Party tags: `party` (name), `partyType`, `partyRole`, `attorney`, `partyText`, `prisonerNumber`.
- Judge tags: `judge` (originating judge fields).
- Docket tags: `docketText`, `docketTextDate`, and related fields for docket entry metadata.

Implementation implications
- Store all PACER fields (top-level case fields plus nested party/courtCase fields) to support future analysis.
- Preserve PACER case identifiers exactly (`courtId`, `caseNumberFull`) to avoid collisions.
- Always persist `receipt` metadata per search run for cost tracking and auditability.
