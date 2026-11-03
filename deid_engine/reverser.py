"""
Stage 5: Bidirectional Reversal & Cloud Re-Identification Engine.
Supports:
1. Combining (De-Identified PDF + Key Vault) -> Restored Original PDF (with original CJK & Latin text, sizes, and colors).
2. Combining (Cloud Analysis Output [.csv/.json/.md/.txt/.pdf] + Key Vault) -> Re-Identified Patient Report.
"""

import hashlib
import os
from typing import Dict, List, Optional, Tuple
import pymupdf

from .vault import CoordinateRestorationRecord, DocumentVaultEntry, ReIdVault


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_matching_vault_entry(pdf_path: str, vault: ReIdVault) -> Optional[DocumentVaultEntry]:
    """
    Locate the DocumentVaultEntry corresponding to `pdf_path` by SHA-256 hash,
    filename, or embedded patient token.
    """
    sha = _file_sha256(pdf_path)
    fname = os.path.basename(pdf_path)

    for entry in vault.documents:
        if entry.deidentified_sha256 == sha:
            return entry
    for entry in vault.documents:
        if entry.deidentified_filename == fname:
            return entry

    # Fallback: check if any patient_token appears in the first 2 pages of the PDF
    try:
        doc = pymupdf.open(pdf_path)
        sample_text = ""
        for i in range(min(2, len(doc))):
            sample_text += doc[i].get_text("text")
        doc.close()
        for entry in vault.documents:
            if entry.patient_token in sample_text:
                return entry
    except Exception:
        pass

    return vault.documents[0] if len(vault.documents) == 1 else None


def reverse_deidentified_pdf(
    deidentified_pdf_path: str,
    vault: ReIdVault,
    output_pdf_path: Optional[str] = None,
) -> Tuple[str, int]:
    """
    Combine a De-Identified PDF and a ReIdVault to reconstruct the original PDF
    with all original CJK and Latin PHI spans restored to their exact coordinates,
    font sizes, and colors.
    Returns `(restored_pdf_path, num_spans_restored)`.
    """
    entry = find_matching_vault_entry(deidentified_pdf_path, vault)
    if entry is None:
        raise ValueError(
            f"No matching document entry found in the Re-ID Key Vault for '{os.path.basename(deidentified_pdf_path)}'."
        )

    if output_pdf_path is None:
        base_dir = os.path.dirname(deidentified_pdf_path)
        output_pdf_path = os.path.join(base_dir, f"RESTORED_{entry.original_filename}")

    doc = pymupdf.open(deidentified_pdf_path)

    records_by_page: Dict[int, List[CoordinateRestorationRecord]] = {}
    for rec in entry.coordinate_records:
        records_by_page.setdefault(rec.page_num, []).append(rec)

    restored_count = 0

    for page_num, page_recs in records_by_page.items():
        if page_num >= len(doc):
            continue
        page = doc[page_num]

        # Step 1: Redact the pseudonym tokens
        for rec in page_recs:
            tx0, ty0, tx1, ty1 = rec.token_bbox
            t_rect = pymupdf.Rect(tx0 + 0.3, ty0 + 0.8, tx1 - 0.3, ty1 - 0.6)
            page.add_redact_annot(t_rect, fill=False)

        page.apply_redactions(
            images=pymupdf.PDF_REDACT_IMAGE_NONE,
            graphics=pymupdf.PDF_REDACT_LINE_ART_NONE,
        )

        # Step 2: Re-insert each original span at its exact baseline origin, font size, and color
        # Using pymupdf.TextWriter + pymupdf.Font('cjk') embeds true CJK glyphs cross-platform (Mac & PC)
        f_cjk = pymupdf.Font("cjk")
        f_tiro = pymupdf.Font("tiro")
        f_helv = pymupdf.Font("helv")

        for rec in page_recs:
            if rec.original_spans:
                for sp in rec.original_spans:
                    rgb_color = pymupdf.sRGB_to_pdf(int(sp["color_int"]))
                    ox, oy = float(sp["origin"][0]), float(sp["origin"][1])
                    fsize = float(sp["size"])
                    is_cjk = bool(sp["is_cjk"])
                    orig_font = str(sp.get("font", ""))
                    if is_cjk:
                        font_obj = f_cjk
                    elif "Times" in orig_font:
                        font_obj = f_tiro
                    else:
                        font_obj = f_helv

                    tw = pymupdf.TextWriter(page.rect, color=rgb_color)
                    tw.append(pymupdf.Point(ox, oy), sp["text"], font=font_obj, fontsize=fsize)
                    tw.write_text(page)
            else:
                rgb_color = pymupdf.sRGB_to_pdf(rec.color_int)
                ox, oy = rec.origin[0], rec.origin[1]
                tw = pymupdf.TextWriter(page.rect, color=rgb_color)
                tw.append(pymupdf.Point(ox, oy), rec.raw_value, font=f_cjk, fontsize=rec.fontsize)
                tw.write_text(page)
            restored_count += 1

    if entry.original_metadata:
        try:
            doc.set_metadata(entry.original_metadata)
        except Exception:
            pass

    doc.save(output_pdf_path, garbage=4, deflate=True, clean=True)
    doc.close()
    return output_pdf_path, restored_count


def reidentify_text_content(text: str, vault: ReIdVault) -> Tuple[str, int]:
    """
    Replace all pseudonym tokens in `text` (from cloud CSV, JSON, Markdown, or TXT output)
    with their original PHI values stored in `vault`.
    Returns `(reidentified_text, replacement_count)`.
    """
    merged_dict: Dict[str, str] = dict(vault.global_token_dictionary)
    for doc_entry in vault.documents:
        for tok, orig in doc_entry.entity_dictionary.items():
            merged_dict[tok] = orig

    # Sort tokens longest-first so 'ORD-XXXXXX-01' matches before any prefix
    sorted_tokens = sorted(merged_dict.keys(), key=len, reverse=True)
    total_replacements = 0
    out_text = text

    for tok in sorted_tokens:
        if tok in out_text:
            count = out_text.count(tok)
            out_text = out_text.replace(tok, merged_dict[tok])
            total_replacements += count

    return out_text, total_replacements


def reidentify_cloud_file(
    cloud_file_path: str,
    vault: ReIdVault,
    output_path: Optional[str] = None,
) -> Tuple[str, int]:
    """
    Combine a cloud analysis file (.csv, .json, .md, .txt, .tsv, .html, or .pdf)
    with `vault` to produce a re-identified file.
    """
    ext = os.path.splitext(cloud_file_path)[1].lower()
    if ext == ".pdf":
        return reverse_deidentified_pdf(cloud_file_path, vault, output_path)

    with open(cloud_file_path, "r", encoding="utf-8") as f:
        content = f.read()

    reid_content, count = reidentify_text_content(content, vault)

    if output_path is None:
        base_dir = os.path.dirname(cloud_file_path)
        fname = os.path.basename(cloud_file_path)
        output_path = os.path.join(base_dir, f"REIDENTIFIED_{fname}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(reid_content)

    return output_path, count
