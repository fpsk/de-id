"""
Stage 4: True Physical PDF Redactor & Sanitizer.
Physically removes PHI glyphs from the PDF stream while preserving background artwork
and vector table borders, renders style-matched pseudonym tokens, wipes all PDF/XMP
metadata, and produces a DocumentVaultEntry for lossless reversal.
"""

from dataclasses import asdict
import hashlib
import os
from typing import Dict, List, Optional, Tuple
import pymupdf

from .phi_detector import PHIMatch, detect_phi_in_document
from .spatial_parser import parse_page_layout
from .tokenizer import BatchTokenizer
from .vault import CoordinateRestorationRecord, DocumentVaultEntry


def _compute_file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def deidentify_pdf_file(
    input_pdf_path: str,
    output_dir: str,
    tokenizer: BatchTokenizer,
    custom_matches: Optional[List[PHIMatch]] = None,
) -> Tuple[str, DocumentVaultEntry, List[PHIMatch]]:
    """
    De-identify a single PDF file, write the sanitized PDF to `output_dir`,
    and return `(output_pdf_path, vault_entry, detected_matches)`.
    """
    os.makedirs(output_dir, exist_ok=True)
    orig_sha256 = _compute_file_sha256(input_pdf_path)
    source_filename = os.path.basename(input_pdf_path)

    doc = pymupdf.open(input_pdf_path)
    original_metadata = dict(doc.metadata or {})

    # Stage 1 & 2: Parse spatial layouts and detect PHI if not pre-supplied
    if custom_matches is not None:
        matches = custom_matches
    else:
        layouts = [parse_page_layout(doc[i], i) for i in range(len(doc))]
        matches = detect_phi_in_document(layouts, filename=source_filename)

    # Stage 3: Assign patient-consistent tokens
    patient_token, deid_filename, doc_entity_dict = tokenizer.assign_tokens(
        matches, source_filename
    )

    coord_records: List[CoordinateRestorationRecord] = []

    # Group matches by page
    matches_by_page: Dict[int, List[PHIMatch]] = {}
    for m in matches:
        matches_by_page.setdefault(m.page_num, []).append(m)

    # Stage 4: Physical stream redaction + style-matched token rendering
    for page_num, page_matches in matches_by_page.items():
        page = doc[page_num]

        # 4A. Add inset redaction annotations so adjacent colons ':' or borders are untouched
        for m in page_matches:
            x0, y0, x1, y1 = m.bbox
            w = x1 - x0
            h = y1 - y0
            inset_x = min(0.6, w * 0.05)
            inset_y = min(1.0, h * 0.12)
            redact_rect = pymupdf.Rect(
                x0 + inset_x,
                y0 + inset_y,
                x1 - inset_x,
                y1 - inset_y,
            )
            page.add_redact_annot(redact_rect, fill=False)

        # Physically strip underlying text glyphs while keeping clean background images & line art
        page.apply_redactions(
            images=pymupdf.PDF_REDACT_IMAGE_NONE,
            graphics=pymupdf.PDF_REDACT_LINE_ART_NONE,
        )

        # 4B. Render replacement tokens in matching color and size
        for m in page_matches:
            rgb_color = pymupdf.sRGB_to_pdf(m.color_int)
            orig_w = max(10.0, m.bbox[2] - m.bbox[0])
            render_size = round(m.fontsize, 2)

            # Prevent vertical crowding if another redacted line is closely stacked (<15pt)
            for other_m in page_matches:
                if other_m is not m:
                    dy = abs(other_m.origin[1] - m.origin[1])
                    if 2.0 < dy < render_size * 0.95:
                        render_size = round(dy * 0.82, 2)

            # Calculate token width and scale slightly if needed to fit tight table cells
            tok_w = pymupdf.get_text_length(m.token, fontname="helv", fontsize=render_size)
            if tok_w > orig_w * 1.35 and render_size > 5.5:
                scale = (orig_w * 1.25) / max(1.0, tok_w)
                render_size = max(5.0, round(render_size * scale, 2))
                tok_w = pymupdf.get_text_length(m.token, fontname="helv", fontsize=render_size)

            ox, oy = m.origin
            page.insert_text(
                pymupdf.Point(ox, oy),
                m.token,
                fontname="helv",
                fontsize=render_size,
                color=rgb_color,
            )

            token_bbox = [
                round(ox, 3),
                round(oy - render_size * 0.88, 3),
                round(ox + tok_w + 1.5, 3),
                round(oy + render_size * 0.25, 3),
            ]

            coord_records.append(
                CoordinateRestorationRecord(
                    page_num=page_num,
                    original_bbox=[round(v, 3) for v in m.bbox],
                    token_bbox=token_bbox,
                    origin=[round(ox, 3), round(oy, 3)],
                    fontsize=render_size,
                    color_int=m.color_int,
                    token_text=m.token,
                    category=m.category,
                    raw_value=m.raw_value,
                    original_spans=[asdict(sp) for sp in m.original_spans],
                )
            )

    # 4C. Scrub all PDF metadata & XMP XML streams
    doc.set_metadata(
        {
            "title": f"HIPAA De-Identified Clinical Report ({patient_token})",
            "author": "",
            "subject": "",
            "keywords": "",
            "creator": "",
            "producer": "HIPAA Safe Harbor De-ID Engine",
            "creationDate": "",
            "modDate": "",
        }
    )
    try:
        doc.del_xml_metadata()
    except Exception:
        pass

    output_pdf_path = os.path.join(output_dir, deid_filename)
    # Save with garbage=4 to physically purge unreferenced text streams from the PDF binary
    doc.save(output_pdf_path, garbage=4, deflate=True, clean=True)
    doc.close()

    deid_sha256 = _compute_file_sha256(output_pdf_path)

    vault_entry = DocumentVaultEntry(
        patient_token=patient_token,
        original_filename=source_filename,
        deidentified_filename=deid_filename,
        original_sha256=orig_sha256,
        deidentified_sha256=deid_sha256,
        original_metadata=original_metadata,
        entity_dictionary=doc_entity_dict,
        coordinate_records=coord_records,
    )

    return output_pdf_path, vault_entry, matches
