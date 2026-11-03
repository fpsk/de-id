"""
Stage 2: Multi-Pass Deterministic PHI Detector.
Implements:
- Pass 1: 2D Semantic Anchor Extraction (Intra-segment, Right-neighbor, and Vertical-stack)
- Pass 2: Self-Bootstrapping Entity Family Propagation across all pages & filenames
- Pass 3: Universal HIPAA Safe Harbor Pattern & Regex Scanner
- Pass 4: Biomedical & Scientific Literature Whitelist Guard
"""

from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Set, Tuple

from .spatial_parser import LineSegment, OriginalSpanRecord, PageLayout, is_cjk_char
from .whitelist import is_whitelisted_value


@dataclass
class PHIMatch:
    page_num: int
    category: str  # PATIENT_NAME, DOB, MRN, ORDER_ID, SPECIMEN_ID, PHYSICIAN, FACILITY, FACILITY_ID, DATE, OTHER_ID
    raw_value: str
    canonical_key: str  # Normalized key for entity resolution across pages/files
    bbox: Tuple[float, float, float, float]
    origin: Tuple[float, float]
    fontsize: float
    color_int: int
    font: str
    original_spans: List[OriginalSpanRecord] = field(default_factory=list)
    token: str = ""


# Exact standalone anchor labels (case-insensitive) for 2D right-neighbor or vertical-stack matching
STANDALONE_ANCHORS: Dict[str, str] = {
    "PATIENT": "PATIENT_NAME",
    "PATIENT NAME": "PATIENT_NAME",
    "NAME": "PATIENT_NAME",
    "DATE OF BIRTH": "DOB",
    "DOB": "DOB",
    "BIRTH DATE": "DOB",
    "MEDICAL RECORD #": "MRN",
    "MEDICAL RECORD NO": "MRN",
    "MRN": "MRN",
    "ORDERED TEST #": "ORDER_ID",
    "ORDER #": "ORDER_ID",
    "ORDER ID": "ORDER_ID",
    "ACCESSION #": "ORDER_ID",
    "SPECIMEN ID": "SPECIMEN_ID",
    "SAMPLE ID": "SPECIMEN_ID",
    "ORDERING PHYSICIAN": "PHYSICIAN",
    "REFERRING PHYSICIAN": "PHYSICIAN",
    "MEDICAL FACILITY": "FACILITY",
    "MEDICAL FACILITY ID": "FACILITY_ID",
    "FACILITY ID": "FACILITY_ID",
    "REPORT DATE": "REPORT_DATE",
    "SPECIMEN COLLECTION DATE": "COLLECTION_DATE",
    "COLLECTION DATE": "COLLECTION_DATE",
    "SPECIMEN RECEIVED": "RECEIVED_DATE",
    "RECEIVED DATE": "RECEIVED_DATE",
}

# Intra-segment prefix patterns: (Regex with group 'val', Category)
INTRA_SEGMENT_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # CJK Anchors
    (re.compile(r"^受\s*檢\s*者\s*[：:]\s*(?P<val>.+)$"), "PATIENT_NAME"),
    (re.compile(r"^(?:病\s*患|病\s*人|患\s*者)?\s*姓\s*名\s*[：:]\s*(?P<val>.+)$"), "PATIENT_NAME"),
    (re.compile(r"^(?:主\s*治\s*|送\s*檢\s*|開\s*單\s*)?醫\s*師\s*[：:]\s*(?P<val>.+)$"), "PHYSICIAN"),
    (re.compile(r"^(?:出\s*生\s*日\s*期|生\s*日)\s*[：:]\s*(?P<val>.+)$"), "DOB"),
    (re.compile(r"^病\s*歷\s*號\s*碼?\s*[：:]\s*(?P<val>.+)$"), "MRN"),
    (re.compile(r"^身\s*分\s*證\s*字\s*號\s*[：:]\s*(?P<val>.+)$"), "MRN"),
    (re.compile(r"^(?:報\s*告|醫\s*令|檢\s*驗)\s*編\s*號\s*[：:]\s*(?P<val>.+)$"), "ORDER_ID"),
    (re.compile(r"^(?:檢\s*體|樣\s*本)\s*編\s*號\s*[：:]\s*(?P<val>.+)$"), "SPECIMEN_ID"),
    (re.compile(r"^(?:檢\s*測\s*地\s*點|醫\s*療\s*院\s*所|送\s*檢\s*單\s*位)\s*[：:]\s*(?P<val>.+)$"), "FACILITY"),
    (re.compile(r"^報\s*告\s*日\s*期\s*[：:]\s*(?P<val>.+)$"), "REPORT_DATE"),
    (re.compile(r"^(?:採\s*檢|收\s*件)\s*日\s*期\s*[：:]\s*(?P<val>.+)$"), "COLLECTION_DATE"),
    # English Anchors within same segment
    (re.compile(r"^(?:PATIENT\s+NAME|NAME)\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "PATIENT_NAME"),
    (re.compile(r"^(?:DATE\s+OF\s+BIRTH|DOB|BIRTH\s+DATE)\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "DOB"),
    (re.compile(r"^(?:MEDICAL\s+RECORD\s*#|MEDICAL\s+RECORD\s+NO\.?|MRN|PATIENT\s+ID)\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "MRN"),
    (re.compile(r"^(?:ORDERED\s+TEST\s*#|ORDER\s*#|ACCESSION\s*#)\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "ORDER_ID"),
    (re.compile(r"^(?:SPECIMEN\s+ID|SAMPLE\s+ID)\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "SPECIMEN_ID"),
    (re.compile(r"^(?:ORDERING\s+PHYSICIAN|REFERRING\s+PHYSICIAN|PATHOLOGIST)\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "PHYSICIAN"),
    (re.compile(r"^MEDICAL\s+FACILITY\s+ID\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "FACILITY_ID"),
    (re.compile(r"^MEDICAL\s+FACILITY\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "FACILITY"),
    (re.compile(r"^SPECIMEN\s+COLLECTION\s+DATE\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "COLLECTION_DATE"),
    (re.compile(r"^SPECIMEN\s+RECEIVED(?:\s+DATE)?\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "RECEIVED_DATE"),
    (re.compile(r"^REPORT\s+DATE\s*[:#]?\s+(?P<val>.+)$", re.IGNORECASE), "REPORT_DATE"),
]

# Signature line pattern: e.g., "Electronically signed by Douglas Lin, M.D. | 16 September 2026"
SIGNATURE_DATE_PATTERN = re.compile(
    r"Electronically\s+signed\s+by\s+[^|]+\|\s*(?P<val>\d{1,2}\s+[A-Za-z]+\s+\d{4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})",
    re.IGNORECASE,
)

# Standalone Hospital / Clinic Title Line Pattern (e.g. Page 1 cover top-left)
FACILITY_STANDALONE_PATTERN = re.compile(
    r"^(?:(?:國立|臺北|臺中|高雄|花蓮|嘉義|屏東)?[^\s]{2,12}(?:總醫院|紀念醫院|大學附設醫院|醫療財團法人[^\s]*醫院|醫院|醫學中心)|"
    r"[A-Z][A-Za-z\s,&\-]{3,50}\b(?:Veterans\s+General\s+Hospital|General\s+Hospital|Memorial\s+Hospital|University\s+Hospital|Medical\s+Center|Cancer\s+Center))$",
)

# Date normalization & regexes
MONTH_MAP = {
    "jan": 1, "january": 1,
    "feb": 2, "february": 2,
    "mar": 3, "march": 3,
    "apr": 4, "april": 4,
    "may": 5,
    "jun": 6, "june": 6,
    "jul": 7, "july": 7,
    "aug": 8, "august": 8,
    "sep": 9, "sept": 9, "september": 9,
    "oct": 10, "october": 10,
    "nov": 11, "november": 11,
    "dec": 12, "december": 12,
}

CJK_DATE_RE = re.compile(r"(?P<y>\d{4})\s*年\s*(?P<m>\d{1,2})\s*月\s*(?P<d>\d{1,2})\s*日")
EN_DATE_RE = re.compile(
    r"\b(?P<d>\d{1,2})\s+(?P<m>Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
    r"Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(?P<y>\d{4})\b",
    re.IGNORECASE,
)
ISO_DATE_RE = re.compile(r"\b(?P<y>19\d{2}|20\d{2})[-/.](?P<m>0?[1-9]|1[0-2])[-/.](?P<d>0?[1-9]|[12]\d|3[01])\b")

# Universal HIPAA Safe Harbor fallback patterns
TW_NATIONAL_ID_RE = re.compile(r"\b[A-Z][12]\d{8}\b")
US_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
ORDER_ACCESSION_RE = re.compile(r"\bORD-\d{5,10}-\d{2}\b")


def normalize_date_canonical(val: str) -> Optional[str]:
    """Convert any date format ('1980 年 1 月 15 日', '15 January 1980', '16 Sep 2026') to 'YYYY-MM-DD'."""
    m = CJK_DATE_RE.search(val)
    if m:
        return f"{int(m.group('y')):04d}-{int(m.group('m')):02d}-{int(m.group('d')):02d}"
    m = EN_DATE_RE.search(val)
    if m:
        mon = MONTH_MAP.get(m.group("m").lower()[:3], 1)
        return f"{int(m.group('y')):04d}-{mon:02d}-{int(m.group('d')):02d}"
    m = ISO_DATE_RE.search(val)
    if m:
        return f"{int(m.group('y')):04d}-{int(m.group('m')):02d}-{int(m.group('d')):02d}"
    return None


def canonicalize_entity_key(category: str, raw_val: str) -> str:
    """
    Produce a canonical entity key so variants like:
    - '1234567A' and '001234567A' -> 'MRN:1234567A'
    - '16 Sep 2026', '16 September 2026', '2026 年 9 月 16 日' -> 'DATE:2026-09-16'
    - '王小明 WANG, HSIAO-MING' and 'Wang, Hsiao-Ming' -> 'PATIENT_NAME:WANG, HSIAO-MING'
    map to the same underlying entity.
    """
    cleaned = raw_val.strip()
    if category in ("DOB", "REPORT_DATE", "COLLECTION_DATE", "RECEIVED_DATE", "DATE"):
        iso = normalize_date_canonical(cleaned)
        if iso:
            prefix = "DOB" if category == "DOB" else "DATE"
            return f"{prefix}:{iso}"
    if category == "MRN":
        # Strip leading zeros for canonical matching ('001234567A' -> '1234567A')
        stripped = cleaned.lstrip("0") or cleaned
        return f"MRN:{stripped.upper()}"
    if category in ("PATIENT_NAME", "PHYSICIAN"):
        # Extract Latin part if present for canonical linking across bilingual pages
        latin_part = "".join(ch for ch in cleaned if not is_cjk_char(ch)).strip()
        if latin_part:
            norm_latin = re.sub(r"\s+", " ", latin_part).upper()
            return f"{category}:{norm_latin}"
        norm_cjk = re.sub(r"\s+", "", cleaned)
        return f"{category}:{norm_cjk}"
    if category == "FACILITY":
        return "FACILITY:PRIMARY"
    norm_clean = re.sub(r"\s+", " ", cleaned).upper()
    return f"{category}:{norm_clean}"


# Known structural column header labels that are never PHI values
NON_VALUE_HEADER_LABELS: Set[str] = set(STANDALONE_ANCHORS.keys()) | {
    "TUMOR TYPE",
    "COUNTRY CODE",
    "DISEASE",
    "SEX",
    "ADDITIONAL RECIPIENT",
    "PATHOLOGIST",
    "SPECIMEN TYPE",
    "BIOMARKER FINDINGS",
    "GENOMIC FINDINGS",
    "CLINICAL TRIALS",
    "APPENDIX",
}


def _rects_overlap(r1: Tuple[float, float, float, float], r2: Tuple[float, float, float, float]) -> bool:
    """Return True if two bounding boxes overlap significantly (>50% of vertical height)."""
    ix0 = max(r1[0], r2[0])
    iy0 = max(r1[1], r2[1])
    ix1 = min(r1[2], r2[2])
    iy1 = min(r1[3], r2[3])
    if (ix1 - ix0) <= 1.0 or (iy1 - iy0) <= 1.0:
        return False
    min_h = max(1.0, min(r1[3] - r1[1], r2[3] - r2[1]))
    return (iy1 - iy0) > 0.45 * min_h


def detect_phi_in_document(pages: List[PageLayout], filename: str = "") -> List[PHIMatch]:
    """
    Run the 4-Pass Deterministic PHI Detection Pipeline across all PageLayouts of a PDF.
    """
    matches: List[PHIMatch] = []

    def add_match(seg: LineSegment, start: int, end: int, category: str) -> Optional[PHIMatch]:
        # Trim leading/trailing whitespace
        while start < end and seg.text[start].isspace():
            start += 1
        while end > start and seg.text[end - 1].isspace():
            end -= 1
        if start >= end:
            return None

        raw_val = seg.text[start:end]
        if is_whitelisted_value(raw_val, line_context=seg.text):
            return None

        bbox = seg.substring_bbox(start, end)
        if not bbox:
            return None

        # Avoid duplicate overlapping matches on the same page
        for existing in matches:
            if existing.page_num == seg.page_num and _rects_overlap(existing.bbox, bbox):
                return None

        origin, size, color_int, font = seg.substring_style(start, end)
        orig_spans = seg.substring_original_spans(start, end)
        canon_key = canonicalize_entity_key(category, raw_val)

        m = PHIMatch(
            page_num=seg.page_num,
            category=category,
            raw_value=raw_val,
            canonical_key=canon_key,
            bbox=bbox,
            origin=origin,
            fontsize=size,
            color_int=color_int,
            font=font,
            original_spans=orig_spans,
        )
        matches.append(m)
        return m

    # =========================================================================
    # PASS 1: 2D Semantic Anchor Extraction
    # =========================================================================
    for page in pages:
        segs = page.segments
        for i, seg in enumerate(segs):
            txt_clean = seg.text.strip()
            txt_upper = re.sub(r"\s+", " ", txt_clean).upper()

            # 1A. Intra-segment Label: Value patterns
            matched_intra = False
            for pat, cat in INTRA_SEGMENT_PATTERNS:
                m = pat.match(seg.text)
                if m:
                    val_start, val_end = m.span("val")
                    add_match(seg, val_start, val_end, cat)
                    matched_intra = True
                    break
            if matched_intra:
                continue

            # 1B. Signature line date pattern
            m_sig = SIGNATURE_DATE_PATTERN.search(seg.text)
            if m_sig:
                val_start, val_end = m_sig.span("val")
                add_match(seg, val_start, val_end, "REPORT_DATE")
                continue

            # 1C. Standalone Hospital / Facility Cover Line
            if FACILITY_STANDALONE_PATTERN.match(txt_clean) and not is_whitelisted_value(txt_clean):
                add_match(seg, 0, len(seg.text), "FACILITY")
                continue

            # 1D. Standalone Anchor Label -> Check Vertical-Stack Below (exact x0 column alignment)
            # or close Right-Neighbor on the same baseline
            if txt_upper in STANDALONE_ANCHORS:
                cat = STANDALONE_ANCHORS[txt_upper]
                found_neighbor = False

                # Check immediate right-hand segment on the same horizontal baseline (within 20pt gap)
                for cand in segs:
                    if cand is seg:
                        continue
                    if (
                        abs(cand.baseline_y - seg.baseline_y) <= 2.5
                        and 0.0 < (cand.bbox[0] - seg.bbox[2]) <= 22.0
                    ):
                        cand_upper = re.sub(r"\s+", " ", cand.text.strip()).upper()
                        if cand_upper not in NON_VALUE_HEADER_LABELS:
                            add_match(cand, 0, len(cand.text), cat)
                            found_neighbor = True
                            break

                # If no close right-hand neighbor, check stacked cell directly below (same column x0 alignment)
                if not found_neighbor:
                    best_below: Optional[LineSegment] = None
                    best_dy = 999.0
                    for cand in segs:
                        if cand is seg:
                            continue
                        dy = cand.baseline_y - seg.baseline_y
                        dx = abs(cand.bbox[0] - seg.bbox[0])
                        if 4.0 <= dy <= 16.0 and dx <= 12.0:
                            cand_upper = re.sub(r"\s+", " ", cand.text.strip()).upper()
                            if cand_upper not in NON_VALUE_HEADER_LABELS and dy < best_dy:
                                best_below = cand
                                best_dy = dy
                    if best_below is not None:
                        add_match(best_below, 0, len(best_below.text), cat)

    # =========================================================================
    # PASS 2: Self-Bootstrapping Entity Propagation Across All Pages
    # =========================================================================
    # Build dictionary of discovered surface strings -> (category, canonical_key)
    propagated_phrases: Dict[str, Tuple[str, str]] = {}
    for m in list(matches):
        val = m.raw_value.strip()
        if len(val) >= 2:
            propagated_phrases[val] = (m.category, m.canonical_key)

        # If bilingual string (e.g. '王小明 WANG, HSIAO-MING'), also register CJK and Latin sub-parts
        if m.category in ("PATIENT_NAME", "PHYSICIAN"):
            cjk_part = "".join(ch for ch in val if is_cjk_char(ch)).strip()
            latin_part = "".join(ch for ch in val if not is_cjk_char(ch)).strip()
            if len(cjk_part) >= 2:
                propagated_phrases[cjk_part] = (m.category, m.canonical_key)
            if len(latin_part) >= 3:
                propagated_phrases[latin_part] = (m.category, m.canonical_key)
                propagated_phrases[latin_part.title()] = (m.category, m.canonical_key)
                propagated_phrases[latin_part.upper()] = (m.category, m.canonical_key)

        # If MRN has leading zeros, register both forms
        if m.category == "MRN":
            stripped = val.lstrip("0")
            if len(stripped) >= 5:
                propagated_phrases[stripped] = (m.category, m.canonical_key)

    # Sort phrases longest-first so full names match before substrings
    sorted_phrases = sorted(propagated_phrases.keys(), key=len, reverse=True)

    for page in pages:
        for seg in page.segments:
            if is_whitelisted_value(seg.text, line_context=seg.text):
                continue
            for phrase in sorted_phrases:
                if phrase in seg.text:
                    cat, _ = propagated_phrases[phrase]
                    start_idx = 0
                    while True:
                        idx = seg.text.find(phrase, start_idx)
                        if idx == -1:
                            break
                        end_idx = idx + len(phrase)
                        # Check word boundary for Latin strings
                        if not is_cjk_char(phrase[0]):
                            before_ok = idx == 0 or not seg.text[idx - 1].isalnum()
                            after_ok = end_idx == len(seg.text) or not seg.text[end_idx].isalnum()
                            if not (before_ok and after_ok):
                                start_idx = end_idx
                                continue
                        add_match(seg, idx, end_idx, cat)
                        start_idx = end_idx

    # =========================================================================
    # PASS 3: Universal HIPAA Safe Harbor Pattern Scanner (Fallback)
    # =========================================================================
    for page in pages:
        for seg in page.segments:
            if is_whitelisted_value(seg.text, line_context=seg.text):
                continue
            for pat, cat in [
                (ORDER_ACCESSION_RE, "ORDER_ID"),
                (TW_NATIONAL_ID_RE, "MRN"),
                (US_SSN_RE, "MRN"),
                (CJK_DATE_RE, "DATE"),
                (EN_DATE_RE, "DATE"),
                (ISO_DATE_RE, "DATE"),
            ]:
                for m_re in pat.finditer(seg.text):
                    add_match(seg, m_re.start(), m_re.end(), cat)

    # Sort all matches by (page_num, bbox_y0, bbox_x0)
    matches.sort(key=lambda m: (m.page_num, m.bbox[1], m.bbox[0]))
    return matches
