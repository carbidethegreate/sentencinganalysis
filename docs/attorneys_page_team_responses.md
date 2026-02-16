# Attorneys Page Team Responses (Executed Prompt)

Date: 2026-02-16  
Scope: Improve `/attorneys` for paid legal users with complete counsel contact intelligence.

## Role Responses

### Product Manager
- Top tasks: find opposing counsel quickly, identify contact channels, and map counsel to related matters.
- Must show complete contact block and case footprint without jumping to other pages.
- P0: searchable full contact fields + practical sorting and filters + reliable dedup.

### UX Designer
- Keep a compact "at-a-glance" section (name, counts, primary contact) and place exhaustive contact lines in a readable pane.
- Add explicit controls: sort, filter toggles (has email/phone/address), and page-size control.
- Show active filters clearly and keep reset obvious.

### Trial Attorney User
- Need all counsel lines because notices often depend on exact text from docket blocks.
- Need quick sort by most active attorneys and most recently seen.
- Need ability to find counsel by any known fragment: name, phone, email, office line, or case number.

### Litigation Paralegal
- One-click access to copy/paste contact blocks is critical.
- Filter by attorneys that have usable phone/email/address to avoid dead-end records.
- Need larger page sizes when preparing service/notice lists.

### Data Engineer
- Dedup should merge when same name + overlapping identifiers (email/phone), or same name + same org where one row is sparse.
- Keep conservative fallback to avoid over-merging distinct people with common names.
- Continue preserving raw lines exactly for transparency.

### Backend Engineer
- Add sort/filter params to `list_attorneys()` to avoid template-only hacks.
- Keep defaults backward-compatible.
- Compute `contact_count` and expose helper fields to templates.

### Frontend Engineer
- Add filter row for sort + "has contact" toggles + page size.
- Keep full block visible but bounded with an internal scroll area.
- Add a "Copy full contact block" action per card.

### QA Lead
- Verify search across all contact fragments.
- Verify dedup behavior on known duplicates and non-duplicates.
- Verify filters + sort combinations + pagination states.
- Verify copy action produces exact expected block text.

## Prioritized Implementation

### P0
- Add sort modes: most cases, most recent, most contact-rich, name A-Z.
- Add toggles: has email, has phone, has address.
- Add page-size control.
- Add one-click copy of full contact block.

### P1
- Improve filter summary/active-state clarity.
- Improve mobile readability for full contact block.

### P2
- Add export options and saved attorney filter presets.

