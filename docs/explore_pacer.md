# Explore PACER admin playground

The **Explore PACER** page is an admin-only playground for PACER Case Locator (PCL) index exploration.

**Route:** `/admin/pacer/explore`

## What this tool does

* Runs **immediate PCL searches** against:
  * `POST /pcl-public-api/rest/cases/find?page={page}` (Case Search)
  * `POST /pcl-public-api/rest/parties/find?page={page}` (Party Search)
* Lets you:
  * choose a court from the `federal_courts` table (optional for party search),
  * set a date filed range (required for case search, optional for party search),
  * optionally select case types (case search only), and
  * cap the maximum record count.
* Shows:
  * the raw response snippets,
  * an observed-fields coverage summary,
  * PACER receipts and fee fields (as returned), and
  * per-page run logs plus a copyable debug bundle.
* Saves a lightweight **Recent Runs** list (admin-only) with receipts and observed fields so you can review errors without rerunning billable searches.

## What this tool does NOT do

* It does **not** fetch docket entries.
* It does **not** download documents.
* It does **not** expose PACER tokens (`nextGenCSO`) to the browser.

## Environment alignment and search permissions

PACER authentication and PCL search endpoints have separate QA and Production environments. QA and
Production require **different accounts**, and the base URLs must align or PCL will reject requests.

Explore PACER will block runs if:

* `PACER_AUTH_BASE_URL` (auth) and `PCL_BASE_URL` (search) point to different environments, or
* PACER returns a token but indicates a **client code is required for searching**.

In the second case you are authenticated, but search is disabled. Add the PACER client code and re-authorize.

## Cost controls and safety caps

Each page request is a billable PACER search.

Defaults and caps:

* Page size is fixed at 54 for immediate searches; do not send `pageSize` in `/cases/find` payloads.
* Default max records is 54 (one page).
* Maximum pages defaults to 5.

You can change the server-side page cap with:

* `PCL_EXPLORE_MAX_PAGES` (defaults to `5`).

The UI will warn when a request is truncated by safety caps.

## How to use Explore PACER

1. Open **Get PACER Data** and authorize PACER access.
2. Open **Explore PACER**.
3. Choose **Case Search** or **Party Search**.
4. Enter the required fields:
   * Case Search: court + date range (optional case types).
   * Party Search: last name prefix (optional first name, date range, and court).
5. Leave max records at 54 unless you have a specific reason to expand.
6. Click **Run Explore**.

## Handling errors (and copying the debug bundle)

If you see an error:

* **401**: The PACER token likely expired. Re-authorize and retry.
* **406**: PCL rejected the request parameters. Copy the debug bundle and open a fix request.
* **Internal payload validation failed**: The request failed locally before contacting PCL. This means the admin
  UI inputs did not map cleanly to the PCL allowlist. Copy the debug bundle and open a fix request.

To copy the debug bundle:

1. Scroll to the **Copyable run bundle** section.
2. Click **Copy debug bundle**.
3. Paste the bundle into your issue, fix request, or investigation notes.

The debug bundle intentionally excludes secrets and tokens. It includes safe token diagnostics
(present/length/SHA256 prefix) plus environment labels to help debug mismatches without exposing credentials.

## Input and payload validation

Explore PACER uses a strict allowlist to prevent unexpected UI fields from reaching the PCL payloads:

* **UI input validation** records any unexpected POST keys in the debug bundle under
  `unexpected_input_keys` (without failing the run).
* **Payload validation** ensures only allowlisted PCL keys are sent. If the payload fails validation, the
  run stops locally with “Internal payload validation failed before contacting PCL.”

When filing a fix request, include `unexpected_input_keys` from the debug bundle so engineers can
identify which UI changes need to be mapped or ignored.

## Recent run history

Each run writes a lightweight entry to `pacer_explore_runs` with:

* search mode and parameters (no secrets),
* truncated response samples,
* receipts and fee fields returned by PACER,
* observed field summaries, and
* a short error summary (if applicable).

Retention is capped (latest 200 entries), and admins can delete runs manually from the UI.
