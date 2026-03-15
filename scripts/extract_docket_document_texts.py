#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import psycopg
import requests
from lxml import html as lxml_html

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None
try:
    from botocore.config import Config  # type: ignore
except Exception:  # pragma: no cover
    Config = None


HEADER_CASE_RE = re.compile(r"\b\d+:\d{2}-[a-z]{2}-\d+\b", re.IGNORECASE)
HEADER_CASE_ALT_RE = re.compile(r"\b\d{2}-\d{3,5}(?:-\d+)?\b")
HEADER_DOC_RE = re.compile(r"\bDocument\s+\d+\b", re.IGNORECASE)
HEADER_FILED_RE = re.compile(r"\bFiled\s+\d{2}/\d{2}/\d{2,4}\b", re.IGNORECASE)
HEADER_PAGE_RE = re.compile(r"\bPage\s+\d+\s+of\s+\d+\b", re.IGNORECASE)
TOKEN_RE = re.compile(r"[a-z0-9]{3,}", re.IGNORECASE)
WS_RE = re.compile(r"\s+")
LEGAL_ANCHOR_RE = re.compile(
    r"\b("
    r"in the united states district court|"
    r"criminal action|"
    r"order\b|"
    r"judgment\b|"
    r"sentencing\b|"
    r"imprisonment\b|"
    r"supervised release\b|"
    r"special assessment\b|"
    r"by the court"
    r")\b",
    re.IGNORECASE,
)


def _norm(value: str) -> str:
    return WS_RE.sub(" ", value or "").strip()


def _parse_s3_uri(path_value: str) -> Tuple[Optional[str], Optional[str]]:
    raw = (path_value or "").strip()
    if not raw.startswith("s3://"):
        return None, None
    body = raw[5:]
    if "/" not in body:
        return None, None
    bucket, key = body.split("/", 1)
    bucket = bucket.strip()
    key = key.strip()
    if not bucket or not key:
        return None, None
    return bucket, key


def _build_s3_client():
    if boto3 is None:
        return None
    endpoint_url = (
        os.environ.get("PACER_DOCUMENTS_S3_ENDPOINT_URL")
        or os.environ.get("AWS_ENDPOINT_URL_S3")
        or ""
    ).strip() or None
    region_name = (
        os.environ.get("PACER_DOCUMENTS_S3_REGION")
        or os.environ.get("AWS_REGION")
        or ""
    ).strip() or None
    access_key = (
        os.environ.get("PACER_DOCUMENTS_S3_ACCESS_KEY_ID")
        or os.environ.get("AWS_ACCESS_KEY_ID")
        or ""
    ).strip() or None
    secret_key = (
        os.environ.get("PACER_DOCUMENTS_S3_SECRET_ACCESS_KEY")
        or os.environ.get("AWS_SECRET_ACCESS_KEY")
        or ""
    ).strip() or None

    kwargs: Dict[str, Any] = {}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    if region_name:
        kwargs["region_name"] = region_name
    if access_key and secret_key:
        kwargs["aws_access_key_id"] = access_key
        kwargs["aws_secret_access_key"] = secret_key
    if Config is not None:
        kwargs["config"] = Config(signature_version="s3v4")
    return boto3.client("s3", **kwargs)


def _ensure_columns(conn: psycopg.Connection[Any]) -> None:
    specs = {
        "text_status": "TEXT",
        "text_path": "TEXT",
        "text_engine": "TEXT",
        "text_confidence": "DOUBLE PRECISION",
        "text_content": "TEXT",
        "text_char_count": "INTEGER",
        "text_word_count": "INTEGER",
        "text_meta_json": "TEXT",
        "text_extracted_at": "TIMESTAMPTZ",
    }
    with conn.cursor() as cur:
        cur.execute(
            """
            select column_name
            from information_schema.columns
            where table_schema='public'
              and table_name='docket_document_items';
            """
        )
        existing = {row[0] for row in cur.fetchall()}
        for name, typ in specs.items():
            if name in existing:
                continue
            cur.execute(
                f"alter table docket_document_items add column {name} {typ};"
            )
    conn.commit()


def _load_items(
    conn: psycopg.Connection[Any],
    limit: int,
    item_id: Optional[int],
    *,
    force: bool,
    retry_below_confidence: Optional[float],
) -> List[Dict[str, Any]]:
    params: List[Any] = []
    where = ["i.status = 'downloaded'"]
    if item_id is not None:
        where.append("i.id = %s")
        params.append(item_id)
    else:
        if force:
            pass
        elif retry_below_confidence is not None:
            where.append(
                "(i.text_status is null or i.text_status in ('queued','processing','retry') or coalesce(i.text_confidence, 0) < %s)"
            )
            params.append(float(retry_below_confidence))
        else:
            where.append("(i.text_status is null or i.text_status in ('queued','processing','retry'))")
    params.append(limit)
    sql = f"""
        select
            i.id,
            i.job_id,
            j.case_id,
            i.document_number,
            i.source_url,
            i.file_path,
            i.content_type,
            i.bytes,
            i.downloaded_at,
            i.text_status,
            i.text_confidence,
            i.description
        from docket_document_items i
        join docket_document_jobs j on j.id=i.job_id
        where {' and '.join(where)}
        order by i.downloaded_at asc nulls last, i.id asc
        limit %s
    """
    with conn.cursor() as cur:
        cur.execute(sql, params)
        cols = [c.name for c in cur.description]
        out = [dict(zip(cols, row)) for row in cur.fetchall()]
    return out


def _download_s3_to_temp(path_value: str, s3_client: Any, temp_dir: Path) -> Path:
    bucket, key = _parse_s3_uri(path_value)
    if not bucket or not key:
        raise ValueError("Invalid S3 path.")
    filename = Path(key).name or "source.bin"
    target = temp_dir / filename
    s3_client.download_file(bucket, key, str(target))
    return target


def _download_s3_key_to_temp(
    *,
    bucket: str,
    key: str,
    s3_client: Any,
    temp_dir: Path,
) -> Path:
    filename = Path(key).name or "source.bin"
    target = temp_dir / filename
    s3_client.download_file(bucket, key, str(target))
    return target


def _download_local_missing_from_s3(
    *,
    local_path: Path,
    s3_client: Any,
    temp_dir: Path,
) -> Optional[Path]:
    if s3_client is None:
        return None
    bucket = (os.environ.get("PACER_DOCUMENTS_S3_BUCKET") or "").strip()
    if not bucket:
        return None

    normalized = str(local_path).replace("\\", "/")
    match = re.search(r"/(case_\d+/[^/]+)$", normalized)
    if not match:
        return None
    relative_key = match.group(1).strip("/")
    if not relative_key:
        return None

    configured_prefix = (os.environ.get("PACER_DOCUMENTS_S3_PREFIX") or "").strip().strip("/")
    candidate_keys: List[str] = []
    if configured_prefix:
        candidate_keys.append(f"{configured_prefix}/{relative_key}")
    candidate_keys.append(relative_key)
    # Historical uploads used this prefix in earlier runs.
    if configured_prefix != "pacer_documents":
        candidate_keys.append(f"pacer_documents/{relative_key}")

    seen: set[str] = set()
    ordered_keys: List[str] = []
    for key in candidate_keys:
        if not key or key in seen:
            continue
        seen.add(key)
        ordered_keys.append(key)

    for key in ordered_keys:
        try:
            return _download_s3_key_to_temp(
                bucket=bucket,
                key=key,
                s3_client=s3_client,
                temp_dir=temp_dir,
            )
        except Exception:
            continue
    return None


def _resolve_local_source(path_value: str, s3_client: Any, temp_dir: Path) -> Path:
    path_value = (path_value or "").strip()
    if not path_value:
        raise ValueError("Missing file_path.")
    if path_value.startswith("s3://"):
        if s3_client is None:
            raise ValueError("S3 client unavailable for s3:// path.")
        return _download_s3_to_temp(path_value, s3_client, temp_dir)
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        path = (Path(os.getcwd()) / path).resolve()
    if not path.exists() or not path.is_file():
        recovered = _download_local_missing_from_s3(
            local_path=path,
            s3_client=s3_client,
            temp_dir=temp_dir,
        )
        if recovered is not None:
            return recovered
        raise FileNotFoundError(f"File not found: {path}")
    return path


def _pdf_page_count(path: Path) -> int:
    done = subprocess.run(
        ["pdfinfo", str(path)],
        capture_output=True,
        text=True,
    )
    if done.returncode != 0:
        return 0
    for line in done.stdout.splitlines():
        if line.lower().startswith("pages:"):
            raw = line.split(":", 1)[1].strip()
            try:
                return max(0, int(raw))
            except ValueError:
                return 0
    return 0


def _pdftotext_extract(path: Path) -> str:
    done = subprocess.run(
        ["pdftotext", "-layout", str(path), "-"],
        capture_output=True,
        text=True,
    )
    if done.returncode != 0:
        return ""
    return _norm(done.stdout)


def _ocr_extract(path: Path, max_pages: int = 0, dpi: int = 240) -> Tuple[str, List[str]]:
    def _candidate_score(text: str) -> float:
        raw = text or ""
        if not raw:
            return 0.0
        token_count = len(TOKEN_RE.findall(raw))
        alpha = sum(1 for ch in raw if ch.isalpha())
        total = len(raw)
        alpha_ratio = (alpha / total) if total else 0.0
        legal_hits = len(set(m.group(0).lower() for m in LEGAL_ANCHOR_RE.finditer(raw)))
        return token_count + (alpha_ratio * 20.0) + (legal_hits * 8.0)

    with tempfile.TemporaryDirectory(prefix="doc_ocr_") as tmp_dir:
        prefix = Path(tmp_dir) / "page"
        cmd = ["pdftoppm", "-r", str(dpi), "-png", str(path), str(prefix)]
        if max_pages and max_pages > 0:
            cmd = [
                "pdftoppm",
                "-f",
                "1",
                "-l",
                str(max_pages),
                "-r",
                str(dpi),
                "-png",
                str(path),
                str(prefix),
            ]
        ppm = subprocess.run(cmd, capture_output=True, text=True)
        if ppm.returncode != 0:
            return "", []
        images = sorted(Path(tmp_dir).glob("page-*.png"))
        chunks: List[str] = []
        page_headers: List[str] = []
        for image in images:
            best_raw = ""
            best_score = 0.0
            for psm in ("6", "11", "4"):
                ocr = subprocess.run(
                    ["tesseract", str(image), "stdout", "--psm", psm],
                    capture_output=True,
                    text=True,
                )
                if ocr.returncode != 0 or not ocr.stdout:
                    continue
                score = _candidate_score(ocr.stdout)
                if score > best_score:
                    best_score = score
                    best_raw = ocr.stdout
            if not best_raw:
                continue
            text = _norm(best_raw)
            chunks.append(text)
            # Keep top lines where ECF headers/stamps usually appear.
            lines = [ln.strip() for ln in best_raw.splitlines() if ln.strip()]
            header = " | ".join(lines[:8])
            if header:
                page_headers.append(_norm(header))
        return _norm("\n\n".join(chunks)), page_headers


def _classify_html_gate(raw_html: str, extracted_text: str) -> str:
    lowered_raw = (raw_html or "").lower()
    lowered_text = (extracted_text or "").lower()
    if "csologin/login.jsf" in lowered_raw:
        return "pacer_login_redirect"
    if "log in to pacer systems" in lowered_text or "district court login" in lowered_text:
        return "pacer_login_page"
    if (
        "you do not have access to this transcript" in lowered_text
        or (
            "transcript" in lowered_text
            and "court reporter" in lowered_text
            and "public terminal" in lowered_text
        )
    ):
        return "transcript_restricted"
    if "you do not have permission to view this document" in lowered_text:
        return "document_permission_denied"
    if "this document is not available" in lowered_text:
        return "document_unavailable"
    if not (extracted_text or "").strip():
        return "empty_html_text"
    return ""


def _html_extract(path: Path) -> Tuple[str, str]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return "", "html_read_failed"
    try:
        tree = lxml_html.fromstring(raw)
    except Exception:
        text = _norm(raw)
        return text, _classify_html_gate(raw, text)
    for bad in tree.xpath("//script|//style|//noscript|//head"):
        bad.drop_tree()
    text = _norm(tree.text_content())
    return text, _classify_html_gate(raw, text)


def _token_set(text: str) -> set[str]:
    return set(TOKEN_RE.findall((text or "").lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _extract_header_fields(text: str, ocr_headers: List[str]) -> Dict[str, Any]:
    case_hits = sorted(
        set(HEADER_CASE_RE.findall(text or ""))
        | set(HEADER_CASE_ALT_RE.findall(text or ""))
    )
    fields = {
        "case_number_hits": case_hits,
        "document_hits": sorted(set(HEADER_DOC_RE.findall(text or ""))),
        "filed_hits": sorted(set(HEADER_FILED_RE.findall(text or ""))),
        "page_hits": sorted(set(HEADER_PAGE_RE.findall(text or ""))),
        "ocr_header_samples": ocr_headers[:5],
    }
    return fields


def _merge_texts(pdf_text: str, ocr_text: str, ocr_headers: List[str]) -> Tuple[str, str]:
    pdf_len = len(pdf_text)
    ocr_len = len(ocr_text)
    overlap = _jaccard(_token_set(pdf_text), _token_set(ocr_text))
    if pdf_len >= 1000 and overlap >= 0.25:
        base = pdf_text
        strategy = "pdf_primary"
    elif ocr_len >= max(1000, int(pdf_len * 1.2)):
        base = ocr_text
        strategy = "ocr_primary"
    else:
        base = pdf_text if pdf_len >= ocr_len else ocr_text
        strategy = "longest_primary"

    # Keep header/stamp lines explicitly if missing from primary text.
    missing_headers = []
    lowered = base.lower()
    for hdr in ocr_headers[:8]:
        if not hdr:
            continue
        snippet = hdr[:80].lower()
        if snippet and snippet not in lowered:
            missing_headers.append(hdr)
    if missing_headers:
        merged = _norm("[HEADER_OCR] " + " || ".join(missing_headers) + "\n\n" + base)
        strategy = strategy + "+header_ocr"
    else:
        merged = base
    return merged, strategy


def _estimate_confidence(
    merged_text: str,
    pdf_text: str,
    ocr_text: str,
    header_fields: Dict[str, Any],
) -> float:
    score = 0.0
    merged_len = len(merged_text)
    pdf_len = len(pdf_text)
    ocr_len = len(ocr_text)

    score += min(0.45, merged_len / 6000.0)
    score += min(0.20, pdf_len / 6000.0)
    score += min(0.15, ocr_len / 8000.0)
    score += 0.20 * _jaccard(_token_set(pdf_text), _token_set(ocr_text))

    if header_fields.get("case_number_hits"):
        score += 0.06
    if header_fields.get("document_hits"):
        score += 0.05
    if header_fields.get("filed_hits"):
        score += 0.05
    if header_fields.get("page_hits"):
        score += 0.04

    # Handle short but coherent court orders where length-based scoring
    # underestimates quality (for example one-page sealing or scheduling orders).
    tokens = TOKEN_RE.findall(merged_text or "")
    token_count = len(tokens)
    alpha_chars = sum(1 for ch in (merged_text or "") if ch.isalpha())
    total_chars = len(merged_text or "")
    alpha_ratio = (alpha_chars / total_chars) if total_chars else 0.0
    legal_anchor_hits = len(set(m.group(0).lower() for m in LEGAL_ANCHOR_RE.finditer(merged_text or "")))

    if token_count >= 40:
        score += 0.06
    elif token_count >= 20:
        score += 0.03

    if alpha_ratio >= 0.60:
        score += 0.04

    if (
        180 <= merged_len <= 2500
        and header_fields.get("case_number_hits")
        and legal_anchor_hits >= 2
    ):
        score += 0.30

    return round(max(0.0, min(0.99, score)), 4)


def _quality_floor_for_short_order(
    merged_text: str,
    pdf_text: str,
    ocr_text: str,
    header_fields: Dict[str, Any],
    current_confidence: float,
) -> float:
    merged_len = len(merged_text or "")
    pdf_len = len(pdf_text or "")
    ocr_len = len(ocr_text or "")
    legal_anchor_hits = len(
        set(m.group(0).lower() for m in LEGAL_ANCHOR_RE.finditer(merged_text or ""))
    )
    alt_case_hint = bool(HEADER_CASE_ALT_RE.search(merged_text or ""))
    has_header_signal = bool(
        header_fields.get("case_number_hits")
        or header_fields.get("document_hits")
        or header_fields.get("filed_hits")
        or header_fields.get("page_hits")
        or alt_case_hint
    )
    looks_short_order = (
        220 <= merged_len <= 2800
        and ocr_len >= 180
        and pdf_len <= 600
        and has_header_signal
        and legal_anchor_hits >= 2
    )
    if looks_short_order:
        return max(current_confidence, 0.82)
    return current_confidence


def _quality_floor_from_docket_description(
    description: str,
    merged_text: str,
    current_confidence: float,
) -> float:
    desc_l = (description or "").lower()
    text_l = (merged_text or "").lower()
    text_len = len(merged_text or "")
    if not desc_l:
        return current_confidence

    # Sealed placeholders are often intentionally sparse; do not overstate quality.
    if "sealed" in desc_l and text_len < 500:
        return current_confidence

    if "judgment as to" in desc_l and text_len >= 220:
        if "judgment" in text_l or "imprisonment" in text_l:
            return max(current_confidence, 0.82)

    if "sentencing memorandum" in desc_l and text_len >= 700:
        if "sentencing" in text_l:
            return max(current_confidence, 0.80)

    if (
        "order as to" in desc_l
        or "memorandum opinion" in desc_l
        or "opinion and order" in desc_l
    ) and text_len >= 240:
        if "order" in text_l or "court" in text_l:
            return max(current_confidence, 0.78)

    return current_confidence


def _openai_reconcile_if_needed(
    merged_text: str,
    pdf_text: str,
    ocr_text: str,
    header_fields: Dict[str, Any],
    confidence: float,
    *,
    threshold: float,
    enabled: bool,
) -> Tuple[str, float, Dict[str, Any]]:
    if not enabled or confidence >= threshold:
        return merged_text, confidence, {"openai_used": False}

    api_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    model = (os.environ.get("OPENAI_TEXT_VERIFY_MODEL") or "gpt-5.4").strip()
    if not api_key:
        return merged_text, confidence, {"openai_used": False, "reason": "missing_openai_api_key"}

    system_prompt = (
        "You clean legal OCR for federal court PDFs. Preserve all header and stamp details "
        "(case number, document number, filed date/time, page markers). "
        "Return strict JSON with keys: corrected_text, confidence, notes."
    )
    user_payload = {
        "header_fields": header_fields,
        "merged_text": merged_text[:30000],
        "pdf_text_extract": pdf_text[:22000],
        "ocr_text_extract": ocr_text[:22000],
    }
    req = {
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
    }
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=req,
            timeout=180,
        )
        resp.raise_for_status()
        data = resp.json()
        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        parsed = json.loads(content) if content else {}
        corrected = _norm(str(parsed.get("corrected_text") or merged_text))
        try:
            new_conf = float(parsed.get("confidence"))
        except Exception:
            new_conf = confidence
        new_conf = max(0.0, min(0.99, new_conf))
        return corrected, new_conf, {
            "openai_used": True,
            "openai_model": model,
            "openai_notes": parsed.get("notes", ""),
        }
    except Exception as exc:
        return merged_text, confidence, {
            "openai_used": False,
            "openai_error": str(exc),
            "openai_model": model,
        }


def _image_data_url(path: Path) -> str:
    raw = path.read_bytes()
    encoded = base64.b64encode(raw).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _openai_transcribe_image_page(
    image_path: Path,
    *,
    api_key: str,
    model: str,
    timeout: int = 240,
) -> str:
    req = {
        "model": model,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a precise legal document transcriber. "
                    "Transcribe the page exactly as written, including headers, footers, stamps, "
                    "case captions, page numbers, and signatures. "
                    "Do not summarize, normalize, or omit text. Output plain text only."
                ),
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Transcribe this court filing page word-for-word with original line breaks "
                            "as closely as possible."
                        ),
                    },
                    {
                        "type": "image_url",
                        "image_url": {"url": _image_data_url(image_path)},
                    },
                ],
            },
        ],
    }
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=req,
        timeout=timeout,
    )
    resp.raise_for_status()
    payload = resp.json()
    content = (
        payload.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    return _norm(content or "")


def _openai_image_rewrite_if_needed(
    pdf_path: Path,
    merged_text: str,
    confidence: float,
    *,
    threshold: float,
    enabled: bool,
    max_pages: int,
) -> Tuple[str, float, Dict[str, Any]]:
    if not enabled or confidence >= threshold:
        return merged_text, confidence, {"openai_image_used": False}

    api_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    model = (os.environ.get("OPENAI_IMAGE_OCR_MODEL") or "gpt-5.4").strip()
    if not api_key:
        return merged_text, confidence, {"openai_image_used": False, "reason": "missing_openai_api_key"}

    with tempfile.TemporaryDirectory(prefix="openai_img_ocr_") as tmp_dir:
        prefix = Path(tmp_dir) / "page"
        cmd = [
            "pdftoppm",
            "-r",
            str(int(os.environ.get("OPENAI_IMAGE_OCR_DPI", "220"))),
            "-png",
            str(pdf_path),
            str(prefix),
        ]
        if max_pages and max_pages > 0:
            cmd = [
                "pdftoppm",
                "-f",
                "1",
                "-l",
                str(max_pages),
                "-r",
                str(int(os.environ.get("OPENAI_IMAGE_OCR_DPI", "220"))),
                "-png",
                str(pdf_path),
                str(prefix),
            ]
        ppm = subprocess.run(cmd, capture_output=True, text=True)
        if ppm.returncode != 0:
            return merged_text, confidence, {
                "openai_image_used": False,
                "openai_image_error": f"pdftoppm_failed: {ppm.stderr.strip()}",
            }

        images = sorted(Path(tmp_dir).glob("page-*.png"))
        if not images:
            return merged_text, confidence, {
                "openai_image_used": False,
                "openai_image_error": "no_rendered_pages",
            }

        page_texts: List[str] = []
        for index, image in enumerate(images, start=1):
            page_text = _openai_transcribe_image_page(
                image,
                api_key=api_key,
                model=model,
            )
            if page_text:
                page_texts.append(f"[PAGE {index}]\n{page_text}")
            else:
                page_texts.append(f"[PAGE {index}]")
        rewritten = _norm("\n\n".join(page_texts))
        if not rewritten:
            return merged_text, confidence, {
                "openai_image_used": False,
                "openai_image_error": "empty_openai_image_transcription",
                "openai_image_model": model,
            }

        headers = _extract_header_fields(rewritten, [])
        boosted = max(
            confidence,
            _estimate_confidence(rewritten, rewritten, merged_text, headers),
        )
        return rewritten, boosted, {
            "openai_image_used": True,
            "openai_image_model": model,
            "openai_image_pages": len(images),
        }


def _write_text_output(
    case_id: int,
    item_id: int,
    text: str,
    *,
    s3_client: Any,
) -> str:
    bucket = (
        os.environ.get("PACER_DOCUMENT_TEXT_S3_BUCKET")
        or os.environ.get("PACER_DOCUMENTS_S3_BUCKET")
        or ""
    ).strip()
    if bucket and s3_client is not None:
        prefix = (os.environ.get("PACER_DOCUMENT_TEXT_S3_PREFIX") or "pacer_document_texts").strip().strip("/")
        key = f"case_{case_id}/item_{item_id}.txt"
        if prefix:
            key = f"{prefix}/{key}"
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=text.encode("utf-8"),
            ContentType="text/plain; charset=utf-8",
        )
        return f"s3://{bucket}/{key}"

    base_dir = Path(
        (os.environ.get("PACER_DOCUMENT_TEXT_DIR") or "").strip()
        or (Path(os.getcwd()) / "pacer_document_texts")
    )
    target = base_dir / f"case_{case_id}" / f"item_{item_id}.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return str(target)


def _update_item_success(
    conn: psycopg.Connection[Any],
    item_id: int,
    *,
    text_path: str,
    text_content: str,
    confidence: float,
    engine: str,
    meta: Dict[str, Any],
) -> None:
    now = datetime.now(timezone.utc)
    clean_text = text_content or ""
    char_count = len(clean_text)
    word_count = len(TOKEN_RE.findall(clean_text))
    with conn.cursor() as cur:
        cur.execute(
            """
            update docket_document_items
               set text_status = 'completed',
                   text_path = %s,
                   text_engine = %s,
                   text_confidence = %s,
                   text_content = %s,
                   text_char_count = %s,
                   text_word_count = %s,
                   text_meta_json = %s,
                   text_extracted_at = %s,
                   updated_at = %s
             where id = %s
            """,
            (
                text_path,
                engine,
                confidence,
                clean_text,
                char_count,
                word_count,
                json.dumps(meta, ensure_ascii=False),
                now,
                now,
                item_id,
            ),
        )
    conn.commit()


def _update_item_failed(conn: psycopg.Connection[Any], item_id: int, error: str) -> None:
    now = datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.execute(
            """
            update docket_document_items
               set text_status = 'failed',
                   text_meta_json = %s,
                   updated_at = %s
             where id = %s
            """,
            (json.dumps({"error": error}, ensure_ascii=False), now, item_id),
        )
    conn.commit()


def process_one(
    row: Dict[str, Any],
    *,
    s3_client: Any,
    openai_verify: bool,
    openai_image_rewrite: bool,
    openai_threshold: float,
    openai_image_max_pages: int,
    ocr_max_pages: int,
) -> Tuple[str, Dict[str, Any]]:
    item_id = int(row["id"])
    case_id = int(row["case_id"])
    with tempfile.TemporaryDirectory(prefix=f"doc_{item_id}_") as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        source = _resolve_local_source(str(row.get("file_path") or ""), s3_client, temp_dir)
        suffix = source.suffix.lower()
        content_type = (row.get("content_type") or "").lower()
        pdf = suffix == ".pdf" or content_type.startswith("application/pdf")
        html = suffix in {".html", ".htm"} or "text/html" in content_type

        if pdf:
            page_count = _pdf_page_count(source)
            text_pdf = _pdftotext_extract(source)
            text_ocr, ocr_headers = _ocr_extract(source, max_pages=ocr_max_pages)
            merged, merge_strategy = _merge_texts(text_pdf, text_ocr, ocr_headers)
            headers = _extract_header_fields(merged, ocr_headers)
            confidence = _estimate_confidence(merged, text_pdf, text_ocr, headers)
            merged2, confidence2, openai_meta = _openai_reconcile_if_needed(
                merged,
                text_pdf,
                text_ocr,
                headers,
                confidence,
                threshold=openai_threshold,
                enabled=openai_verify,
            )
            confidence2 = _quality_floor_for_short_order(
                merged2,
                text_pdf,
                text_ocr,
                headers,
                confidence2,
            )
            confidence2 = _quality_floor_from_docket_description(
                str(row.get("description") or ""),
                merged2,
                confidence2,
            )
            merged3, confidence3, openai_image_meta = _openai_image_rewrite_if_needed(
                source,
                merged2,
                confidence2,
                threshold=openai_threshold,
                enabled=openai_image_rewrite,
                max_pages=openai_image_max_pages,
            )
            headers_after = _extract_header_fields(merged3, ocr_headers)
            confidence3 = _quality_floor_from_docket_description(
                str(row.get("description") or ""),
                merged3,
                confidence3,
            )
            text_path = _write_text_output(case_id, item_id, merged3, s3_client=s3_client)
            digest = hashlib.sha256(merged3.encode("utf-8")).hexdigest()
            meta = {
                "source_file_path": row.get("file_path"),
                "source_sha256_text": digest,
                "source_content_type": row.get("content_type"),
                "page_count": page_count,
                "pdf_text_chars": len(text_pdf),
                "ocr_text_chars": len(text_ocr),
                "merged_text_chars": len(merged3),
                "merge_strategy": merge_strategy,
                "header_fields": headers_after,
                "openai": openai_meta,
                "openai_image": openai_image_meta,
            }
            return text_path, {
                "confidence": confidence3,
                "engine": "pdftotext+ocr+optional_openai",
                "meta": meta,
                "text": merged3,
            }

        if html:
            text, html_issue = _html_extract(source)
            if html_issue:
                raise ValueError(f"HTML extraction did not produce usable document text ({html_issue}).")
            text_path = _write_text_output(case_id, item_id, text, s3_client=s3_client)
            headers = _extract_header_fields(text, [])
            confidence = _estimate_confidence(text, text, "", headers)
            meta = {
                "source_file_path": row.get("file_path"),
                "source_content_type": row.get("content_type"),
                "merged_text_chars": len(text),
                "header_fields": headers,
                "openai": {"openai_used": False},
            }
            return text_path, {
                "confidence": confidence,
                "engine": "html_text_extract",
                "meta": meta,
                "text": text,
            }

        text = _norm(source.read_text(encoding="utf-8", errors="replace"))
        text_path = _write_text_output(case_id, item_id, text, s3_client=s3_client)
        headers = _extract_header_fields(text, [])
        confidence = _estimate_confidence(text, text, "", headers)
        meta = {
            "source_file_path": row.get("file_path"),
            "source_content_type": row.get("content_type"),
            "merged_text_chars": len(text),
            "header_fields": headers,
            "openai": {"openai_used": False},
        }
        return text_path, {
            "confidence": confidence,
            "engine": "plain_text_extract",
            "meta": meta,
            "text": text,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract high-accuracy text from downloaded docket document files."
    )
    parser.add_argument("--db-url", required=True)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--item-id", type=int, default=None)
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--retry-below-confidence",
        type=float,
        default=None,
        help="Also reprocess completed items when confidence is below this threshold.",
    )
    parser.add_argument("--openai-verify", action="store_true")
    parser.add_argument(
        "--openai-image-rewrite",
        action="store_true",
        help="When confidence is below threshold, transcribe PDF page images with OpenAI to preserve headers/footers.",
    )
    parser.add_argument("--openai-threshold", type=float, default=0.82)
    parser.add_argument(
        "--openai-image-max-pages",
        type=int,
        default=0,
        help="0 means all pages (or OCR page cap); otherwise only first N pages for OpenAI image rewrite.",
    )
    parser.add_argument(
        "--ocr-max-pages",
        type=int,
        default=0,
        help="0 means all pages; otherwise only first N pages OCR.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    db_url = (args.db_url or "").strip()
    if db_url.startswith("postgresql+psycopg://"):
        db_url = "postgresql://" + db_url.split("://", 1)[1]
    elif db_url.startswith("postgresql+psycopg2://"):
        db_url = "postgresql://" + db_url.split("://", 1)[1]
    elif db_url.startswith("postgres://"):
        db_url = "postgresql://" + db_url.split("://", 1)[1]
    s3_client = _build_s3_client()
    with psycopg.connect(db_url) as conn:
        _ensure_columns(conn)
        rows = _load_items(
            conn,
            limit=max(1, int(args.limit)),
            item_id=args.item_id,
            force=bool(args.force),
            retry_below_confidence=args.retry_below_confidence,
        )
        if not rows:
            print("No downloaded document items need text extraction.")
            return
        processed = 0
        failed = 0
        for row in rows:
            item_id = int(row["id"])
            try:
                text_path, result = process_one(
                    row,
                    s3_client=s3_client,
                    openai_verify=bool(args.openai_verify),
                    openai_image_rewrite=bool(args.openai_image_rewrite),
                    openai_threshold=float(args.openai_threshold),
                    openai_image_max_pages=(
                        max(0, int(args.openai_image_max_pages))
                        or max(0, int(args.ocr_max_pages))
                    ),
                    ocr_max_pages=max(0, int(args.ocr_max_pages)),
                )
                _update_item_success(
                    conn,
                    item_id,
                    text_path=text_path,
                    text_content=str(result.get("text") or ""),
                    confidence=float(result["confidence"]),
                    engine=str(result["engine"]),
                    meta=dict(result["meta"]),
                )
                processed += 1
                print(
                    f"[ok] item={item_id} case={row.get('case_id')} "
                    f"confidence={result['confidence']:.2f} text_path={text_path}"
                )
            except Exception as exc:
                failed += 1
                _update_item_failed(conn, item_id, str(exc))
                print(f"[failed] item={item_id} case={row.get('case_id')} error={exc}")
        print(
            json.dumps(
                {
                    "processed": processed,
                    "failed": failed,
                    "total": len(rows),
                    "force": bool(args.force),
                    "retry_below_confidence": args.retry_below_confidence,
                    "openai_verify": bool(args.openai_verify),
                    "openai_image_rewrite": bool(args.openai_image_rewrite),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
