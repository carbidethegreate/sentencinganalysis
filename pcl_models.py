from __future__ import annotations

from typing import Dict

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB


def build_pcl_tables(metadata: MetaData) -> Dict[str, Table]:
    json_type = JSON().with_variant(JSONB, "postgresql")
    case_types_type = JSON().with_variant(ARRAY(String), "postgresql")

    courts = Table(
        "courts",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("court_id", String(50), nullable=False, unique=True),
        Column("court_name", Text, nullable=True),
        Column("court_type", String(40), nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        Column("source_payload", json_type, nullable=False),
    )

    court_import_runs = Table(
        "court_import_runs",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column("status", String(40), nullable=False),
        Column("source", String(80), nullable=True),
        Column("records_fetched", Integer, nullable=True),
        Column("records_inserted", Integer, nullable=True),
        Column("records_updated", Integer, nullable=True),
        Column("completed_at", DateTime(timezone=True), nullable=True),
        Column("details", json_type, nullable=True),
    )

    pcl_batch_searches = Table(
        "pcl_batch_searches",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        Column("court_id", String(50), nullable=False),
        Column("date_filed_from", Date, nullable=False),
        Column("date_filed_to", Date, nullable=False),
        Column("case_types", case_types_type, nullable=False),
        Column("advanced_filters", json_type, nullable=True),
        Column("status", String(40), nullable=False),
        Column("created_by", String(120), nullable=True),
    )

    pcl_batch_requests = Table(
        "pcl_batch_requests",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        Column("court_id", String(50), nullable=False),
        Column("date_filed_from", Date, nullable=False),
        Column("date_filed_to", Date, nullable=False),
        Column("case_types", Text, nullable=False),
        Column("status", String(40), nullable=False),
        Column("last_run_at", DateTime(timezone=True), nullable=True),
    )

    pcl_batch_segments = Table(
        "pcl_batch_segments",
        metadata,
        Column("id", Integer, primary_key=True),
        Column(
            "batch_request_id",
            Integer,
            ForeignKey("pcl_batch_requests.id"),
            nullable=False,
        ),
        Column(
            "parent_segment_id",
            Integer,
            ForeignKey("pcl_batch_segments.id"),
            nullable=True,
        ),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        Column("court_id", String(50), nullable=False),
        Column("date_filed_from", Date, nullable=False),
        Column("date_filed_to", Date, nullable=False),
        Column("case_types", Text, nullable=False),
        Column("status", String(40), nullable=False),
        Column(
            "batch_search_id",
            Integer,
            ForeignKey("pcl_batch_searches.id"),
            nullable=True,
        ),
        Column("segment_from", Date, nullable=True),
        Column("segment_to", Date, nullable=True),
        Column("report_id", String(120), nullable=True),
        Column("remote_status", String(80), nullable=True),
        Column("remote_status_message", Text, nullable=True),
        Column("submitted_at", DateTime(timezone=True), nullable=True),
        Column("completed_at", DateTime(timezone=True), nullable=True),
        Column("next_poll_at", DateTime(timezone=True), nullable=True),
        Column("attempt_count", Integer, nullable=False, server_default="0"),
        Column("attempts", Integer, nullable=False, server_default="0"),
        Column("poll_attempts", Integer, nullable=False, server_default="0"),
        Column("error_message", Text, nullable=True),
        Column("last_error", Text, nullable=True),
        Column("search_payload_json", Text, nullable=True),
    )

    pcl_case_result_raw = Table(
        "pcl_case_result_raw",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column("ingested_at", DateTime(timezone=True), nullable=True),
        Column(
            "segment_id",
            Integer,
            ForeignKey("pcl_batch_segments.id"),
            nullable=False,
        ),
        Column("report_id", String(120), nullable=True),
        Column("court_id", String(50), nullable=True),
        Column("case_number", Text, nullable=True),
        Column("record_hash", String(128), nullable=False, unique=True, index=True),
        Column("payload_json", json_type, nullable=False),
        Index("ix_pcl_case_result_raw_court_case", "court_id", "case_number"),
    )

    pcl_cases = Table(
        "pcl_cases",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        Column("court_id", String(50), nullable=False),
        Column("case_id", String(120), nullable=True),
        Column("case_number", Text, nullable=False),
        Column("case_number_full", Text, nullable=True),
        Column("case_type", String(20), nullable=True),
        Column("date_filed", Date, nullable=True),
        Column("date_closed", Date, nullable=True),
        Column("effective_date_closed", Date, nullable=True),
        Column("short_title", Text, nullable=True),
        Column("case_title", Text, nullable=True),
        Column("case_link", Text, nullable=True),
        Column("case_year", String(10), nullable=True),
        Column("case_office", String(20), nullable=True),
        Column("judge_last_name", String(80), nullable=True),
        Column("source_last_seen_at", DateTime(timezone=True), nullable=True),
        Column("record_hash", String(128), nullable=True),
        Column(
            "last_segment_id",
            Integer,
            ForeignKey("pcl_batch_segments.id"),
            nullable=True,
        ),
        Column("data_json", Text, nullable=False),
        CheckConstraint(
            "case_type in ('cr','crim','ncrim','dcrim')",
            name="ck_pcl_cases_case_type",
        ),
        UniqueConstraint("court_id", "case_number", name="uq_pcl_cases_court_case"),
        Index("ix_pcl_cases_court_date", "court_id", "date_filed"),
        Index(
            "ix_pcl_cases_court_case_number_full",
            "court_id",
            "case_number_full",
        ),
        Index("ix_pcl_cases_case_type", "case_type"),
        Index("ix_pcl_cases_judge_last_name", "judge_last_name"),
    )

    pcl_remote_jobs = Table(
        "pcl_remote_jobs",
        metadata,
        Column("id", Integer, primary_key=True),
        Column(
            "segment_id",
            Integer,
            ForeignKey("pcl_batch_segments.id"),
            nullable=False,
        ),
        Column("remote_job_id", String(120), nullable=False),
        Column("submitted_at", DateTime(timezone=True), nullable=True),
        Column("last_polled_at", DateTime(timezone=True), nullable=True),
        Column("remote_status", String(80), nullable=True),
        Column("deleted_from_pacer_at", DateTime(timezone=True), nullable=True),
    )

    pcl_receipts = Table(
        "pcl_receipts",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "segment_id",
            Integer,
            ForeignKey("pcl_batch_segments.id"),
            nullable=True,
        ),
        Column(
            "remote_job_id",
            Integer,
            ForeignKey("pcl_remote_jobs.id"),
            nullable=True,
        ),
        Column("billable_pages", Integer, nullable=True),
        Column("fee", Integer, nullable=True),
        Column("client_code", String(120), nullable=True),
        Column("description", Text, nullable=True),
        Column("report_id", String(120), nullable=True),
        Column("raw_payload", json_type, nullable=False),
    )

    pcl_batch_receipts = Table(
        "pcl_batch_receipts",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "segment_id",
            Integer,
            ForeignKey("pcl_batch_segments.id"),
            nullable=False,
        ),
        Column("report_id", String(120), nullable=True),
        Column("receipt_json", Text, nullable=False),
    )

    docket_enrichment_jobs = Table(
        "docket_enrichment_jobs",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        Column("case_id", Integer, ForeignKey("pcl_cases.id"), nullable=False, index=True),
        Column(
            "include_docket_text",
            Boolean,
            nullable=False,
            server_default="0",
        ),
        Column("status", String(40), nullable=False, server_default="queued"),
        Column("attempts", Integer, nullable=False, server_default="0"),
        Column("last_error", Text, nullable=True),
        Column("started_at", DateTime(timezone=True), nullable=True),
        Column("finished_at", DateTime(timezone=True), nullable=True),
        Index(
            "ix_docket_enrichment_jobs_case_status",
            "case_id",
            "status",
        ),
    )

    docket_enrichment_receipts = Table(
        "docket_enrichment_receipts",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "job_id",
            Integer,
            ForeignKey("docket_enrichment_jobs.id"),
            nullable=False,
            index=True,
        ),
        Column("billable_pages", Integer, nullable=True),
        Column("fee", Integer, nullable=True),
        Column("description", Text, nullable=True),
        Column("client_code", String(120), nullable=True),
        Column("receipt_json", Text, nullable=False),
    )

    return {
        "courts": courts,
        "court_import_runs": court_import_runs,
        "pcl_batch_searches": pcl_batch_searches,
        "pcl_batch_requests": pcl_batch_requests,
        "pcl_batch_segments": pcl_batch_segments,
        "pcl_remote_jobs": pcl_remote_jobs,
        "pcl_case_result_raw": pcl_case_result_raw,
        "pcl_cases": pcl_cases,
        "pcl_receipts": pcl_receipts,
        "pcl_batch_receipts": pcl_batch_receipts,
        "docket_enrichment_jobs": docket_enrichment_jobs,
        "docket_enrichment_receipts": docket_enrichment_receipts,
    }
