from __future__ import annotations

from typing import Dict

from sqlalchemy import (
    CheckConstraint,
    Column,
    Date,
    DateTime,
    Float,
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


VALID_VARIANCE_TYPES = (
    "within",
    "upward",
    "downward",
    "departure",
    "variance",
    "other",
)

VALID_EVIDENCE_SOURCE_TYPES = (
    "docket_entry",
    "document",
    "manual",
)



def build_sentencing_tables(metadata: MetaData) -> Dict[str, Table]:
    judges = Table(
        "judges",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("name_full", String(255), nullable=False),
        Column("name_first", String(120), nullable=True),
        Column("name_last", String(120), nullable=True, index=True),
        Column("court_id", String(50), nullable=True, index=True),
        Column("source_system", String(80), nullable=True),
        Column("source_ref", String(255), nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        UniqueConstraint("name_full", "court_id", name="uq_judges_name_court"),
    )

    case_judges = Table(
        "case_judges",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("case_id", Integer, ForeignKey("pcl_cases.id"), nullable=False, index=True),
        Column("judge_id", Integer, ForeignKey("judges.id"), nullable=False, index=True),
        Column("role", String(80), nullable=False, server_default="sentencing"),
        Column("confidence", Float, nullable=False, server_default="1"),
        Column("source_system", String(80), nullable=True),
        Column("source_ref", String(255), nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        UniqueConstraint("case_id", "judge_id", "role", name="uq_case_judges_case_judge_role"),
        Index("ix_case_judges_role_confidence", "role", "confidence"),
    )

    sentencing_events = Table(
        "sentencing_events",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("case_id", Integer, ForeignKey("pcl_cases.id"), nullable=False, index=True),
        Column("defendant_identifier", String(255), nullable=True),
        Column("sentencing_date", Date, nullable=False, index=True),
        Column("guideline_range_low", Integer, nullable=True),
        Column("guideline_range_high", Integer, nullable=True),
        Column("offense_level", Integer, nullable=True),
        Column("criminal_history_category", String(20), nullable=True),
        Column("sentence_months", Integer, nullable=False),
        Column("variance_type", String(40), nullable=True),
        Column("notes", Text, nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column(
            "updated_at",
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
        CheckConstraint(
            "guideline_range_low IS NULL OR guideline_range_high IS NULL OR guideline_range_low <= guideline_range_high",
            name="ck_sentencing_events_guideline_range",
        ),
        CheckConstraint(
            "variance_type IS NULL OR variance_type IN ('within', 'upward', 'downward', 'departure', 'variance', 'other')",
            name="ck_sentencing_events_variance_type",
        ),
        Index(
            "ix_sentencing_events_case_date",
            "case_id",
            "sentencing_date",
        ),
    )

    sentencing_evidence = Table(
        "sentencing_evidence",
        metadata,
        Column("id", Integer, primary_key=True),
        Column(
            "sentencing_event_id",
            Integer,
            ForeignKey("sentencing_events.id"),
            nullable=False,
            index=True,
        ),
        Column("source_type", String(40), nullable=False),
        Column("source_id", String(120), nullable=True),
        Column("reference_text", Text, nullable=False),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        CheckConstraint(
            "source_type IN ('docket_entry', 'document', 'manual')",
            name="ck_sentencing_evidence_source_type",
        ),
        Index(
            "ix_sentencing_evidence_event_source",
            "sentencing_event_id",
            "source_type",
        ),
    )

    return {
        "judges": judges,
        "case_judges": case_judges,
        "sentencing_events": sentencing_events,
        "sentencing_evidence": sentencing_evidence,
    }
