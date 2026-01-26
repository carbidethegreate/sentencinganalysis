# PACER PDF parsing reference notes

These notes summarize the local reference repos you provided. They are only for PDF docket parsing and do not scrape PACER.

## Repo: pacer1001 (PACER Docket Parser)
Path: `/Users/david/Desktop/Render/Repos that might be helpful to look at for reference /Pacer_1_migh_be_helpful/Untitled/pacer1001`

Overview
- Purpose: Parse PACER docket PDF files into a CSV docket table + JSON case metadata.
- Pipeline entry point: `src/docketparser/parsers/main_parser.py` (class `MainParser`).
- Output: `docket_df` (combined table rows) and `case_json` (metadata + parties/attorneys blocks).

Key components and what they do
- `src/docketparser/parsers/docket_table_parser.py`
  - Uses layout detection (Detectron2 TableBank model via LayoutParser) to detect table regions.
  - Uses Hough line detection (OpenCV) to derive columns and rows from table images.
  - Builds a grid of text blocks and converts to a DataFrame.
- `src/docketparser/parsers/page_structure_parser.py`
  - Heuristic extraction of party blocks and attorney blocks using bold and underline tokens.
  - Splits left/right columns on page; builds `PlantiffBlock` and `RepresentativeBlock` data.
- `src/docketparser/parsers/text_parser.py`
  - Regex extraction for judge, dates, nature of suit, jurisdiction, lead case, etc.
  - Extracts case flags from a band near top of first page.
- `src/docketparser/parsers/text_helper.py`
  - Decomposes case numbers, extracts MDL codes, and parses judge initials.
- `pdftools/extractor.py`
  - Uses `pdfplumber` to extract tokens + `pdf2image`/Poppler to rasterize pages.

Dependencies (heavy)
- `torch`, `torchvision`, `detectron2`, `layoutparser`, `opencv`, `pdfplumber`, `pdf2image`, `poppler`.
- This is not lightweight for a web worker. Better for an offline batch job or a separate parsing service.

Takeaways for our project
- Useful if we decide to support PDF docket parsing as a separate batch pipeline.
- Table detection + row/column inference can be reused conceptually, but adds large ML deps.
- Regex extraction can help with judge fields and basic metadata if HTML/XML is missing.
- The code assumes a single main docket table per page and merges tables across pages.

## Repo: PacerSample1000
Path: `/Users/david/Desktop/Render/Repos that might be helpful to look at for reference /Pacer_1_migh_be_helpful/Untitled/PacerSample1000`
- This directory only contains a `.git` folder and no working files.


## Repo: pacer1003 (pacerR)
Path: `/Users/david/Desktop/Render/Repos that might be helpful to look at for reference /Pacer_1_migh_be_helpful/Untitled/pacer1003`

Overview
- R package focused on PACER XML docket retrieval (not PCL). Uses browser-like navigation in NextGen CM/ECF.
- Emphasizes fee warnings and rate limiting. Focused on Courts of Appeals in tests.

Useful flow details (R/utils.R)
- Auth uses PACER CSO login; then cookies with `NextGenCSO`.
- Navigates UI endpoints:
  - GET `/n/beam/servlet/TransportRoom?servlet=CaseSearch.jsp`
  - POST `/n/beam/servlet/TransportRoom` with search form fields (`csnum1`, `CSRF`, etc.)
  - Parse CaseSummary link from results page
  - POST form with `fullDocket` to reach filter page
  - POST filter form with `outputXML_TXT=XML`
  - Confirm charge with `confirmCharge=Y` then POST again to get XML
- Shows PACER requires a 2-step confirm charge flow for XML in some courts.

Takeaways for our project
- Confirms that some CM/ECF sites require a multi-step form flow for XML docket output (search -> summary -> filter -> confirm charge). This explains why we sometimes get a docket form instead of the report.
- Useful as a reference for building a robust HTML form flow in the docket enrichment worker if the direct `DktRpt.pl?case_id=` path fails.
- Not PCL API; it is direct NextGen UI navigation and may require extra CSRF handling.

