ALTER TABLE docket_document_items
  ADD COLUMN IF NOT EXISTS request_method TEXT NOT NULL DEFAULT 'GET';

ALTER TABLE docket_document_items
  ADD COLUMN IF NOT EXISTS request_payload_json TEXT;
