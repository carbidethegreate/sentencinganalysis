# Explore PACER admin playground

The **Explore PACER** page is an admin-only playground for PACER Case Locator (PCL) index exploration.

**Route:** `/admin/pacer/explore`

## What this tool does

* Runs **immediate PCL case searches** against `POST /pcl-public-api/rest/cases/find?page={page}`.
* Lets you:
  * choose a court from the `federal_courts` table,
  * set a date filed range,
  * optionally select case types, and
  * cap the maximum record count.
* Shows:
  * the raw response snippets,
  * an observed-fields coverage summary,
  * PACER receipts and fee fields (as returned), and
  * per-page run logs plus a copyable debug bundle.

## What this tool does NOT do

* It does **not** fetch docket entries.
* It does **not** download documents.
* It does **not** expose PACER tokens (`nextGenCSO`) to the browser.

## Cost controls and safety caps

Each page request is a billable PACER search.

Defaults and caps:

* Page size is 54 (PACER default).
* Default max records is 54 (one page).
* Maximum pages defaults to 5.

You can change the server-side page cap with:

* `PCL_EXPLORE_MAX_PAGES` (defaults to `5`).

The UI will warn when a request is truncated by safety caps.

## How to use Explore PACER

1. Open **Get PACER Data** and authorize PACER access.
2. Open **Explore PACER**.
3. Select a court.
4. Choose a date filed range.
5. (Optional) select case types.
6. Leave max records at 54 unless you have a specific reason to expand.
7. Click **Run Explore**.

## Handling errors (and copying the debug bundle)

If you see an error:

* **401**: The PACER token likely expired. Re-authorize and retry.
* **406**: The search parameters were rejected. Copy the debug bundle and open a fix request.

To copy the debug bundle:

1. Scroll to the **Copyable run bundle** section.
2. Click **Copy debug bundle**.
3. Paste the bundle into your issue, fix request, or investigation notes.

The debug bundle intentionally excludes secrets and tokens.
