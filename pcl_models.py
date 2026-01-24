from __future__ import annotations

from typing import Dict

from sqlalchemy import (
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


def build_pcl_tables(metadata: MetaData) -> Dict[str, Table]:
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
        Column("report_id", String(120), nullable=True),
        Column("remote_status", String(80), nullable=True),
        Column("remote_status_message", Text, nullable=True),
        Column("submitted_at", DateTime(timezone=True), nullable=True),
        Column("completed_at", DateTime(timezone=True), nullable=True),
        Column("next_poll_at", DateTime(timezone=True), nullable=True),
        Column("attempt_count", Integer, nullable=False, server_default="0"),
        Column("poll_attempts", Integer, nullable=False, server_default="0"),
        Column("error_message", Text, nullable=True),
        Column("search_payload_json", Text, nullable=True),
    )

    pcl_case_result_raw = Table(
        "pcl_case_result_raw",
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
        Column("court_id", String(50), nullable=True),
        Column("case_number", Text, nullable=True),
        Column("record_hash", String(128), nullable=False, unique=True, index=True),
        Column("payload_json", Text, nullable=False),
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
        Column("case_number", Text, nullable=False),
        Column("case_number_full", Text, nullable=True),
        Column("case_type", String(20), nullable=True),
        Column("date_filed", Date, nullable=True),
        Column("date_closed", Date, nullable=True),
        Column("short_title", Text, nullable=True),
        Column("case_title", Text, nullable=True),
        Column("judge_last_name", String(80), nullable=True),
        Column("record_hash", String(128), nullable=True),
        Column(
            "last_segment_id",
            Integer,
            ForeignKey("pcl_batch_segments.id"),
            nullable=True,
        ),
        Column("data_json", Text, nullable=False),
        UniqueConstraint("court_id", "case_number", name="uq_pcl_cases_court_case"),
        Index("ix_pcl_cases_court_date", "court_id", "date_filed"),
        Index("ix_pcl_cases_case_type", "case_type"),
        Index("ix_pcl_cases_judge_last_name", "judge_last_name"),
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

    return {
        "pcl_batch_requests": pcl_batch_requests,
        "pcl_batch_segments": pcl_batch_segments,
        "pcl_case_result_raw": pcl_case_result_raw,
        "pcl_cases": pcl_cases,
        "pcl_batch_receipts": pcl_batch_receipts,
    }
