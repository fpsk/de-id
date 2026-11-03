#!/usr/bin/env python3
"""
Local Web Application (Flask) for the HIPAA Safe Harbor Non-LLM PDF De-Identification
& Reversal Suite.
Binds strictly to 127.0.0.1 (localhost) so all patient data remains 100% on the local machine.

Launch with:
    python3 webapp.py
Then open:
    http://127.0.0.1:5050
"""

from dataclasses import asdict
import io
import os
import sys
import threading
import uuid
import webbrowser
from typing import Dict, List, Optional
from flask import Flask, jsonify, render_template, request, send_file
import pymupdf

from deid_engine.pdf_redactor import deidentify_pdf_file
from deid_engine.phi_detector import PHIMatch, canonicalize_entity_key, detect_phi_in_document
from deid_engine.reverser import (
    reidentify_cloud_file,
    reidentify_text_content,
    reverse_deidentified_pdf,
)
from deid_engine.spatial_parser import PageLayout, parse_page_layout
from deid_engine.tokenizer import BatchTokenizer
from deid_engine.vault import ReIdVault, load_vault, save_vault

# Support both normal Python execution and standalone PyInstaller Windows .exe
if getattr(sys, "frozen", False):
    BUNDLE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = BUNDLE_DIR

UPLOAD_DIR = os.path.join(BASE_DIR, "webapp_workspace", "uploads")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_deidentified")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

app = Flask(__name__, template_folder=os.path.join(BUNDLE_DIR, "templates"))


class DocumentSession:
    def __init__(self, doc_id: str, pdf_path: str, filename: str):
        self.doc_id = doc_id
        self.pdf_path = pdf_path
        self.filename = filename
        doc = pymupdf.open(pdf_path)
        self.page_count = len(doc)
        self.page_sizes = [(doc[i].rect.width, doc[i].rect.height) for i in range(len(doc))]
        self.layouts: List[PageLayout] = [parse_page_layout(doc[i], i) for i in range(len(doc))]
        doc.close()

        self.matches: List[PHIMatch] = detect_phi_in_document(self.layouts, filename=filename)
        preview_tok = BatchTokenizer(date_mode="mask", batch_salt="WEB-PREVIEW")
        self.patient_token, self.deid_filename, _ = preview_tok.assign_tokens(
            self.matches, filename
        )
        self.disabled_indices: set = set()


SESSIONS: Dict[str, DocumentSession] = {}


def _autoload_sample() -> None:
    if SESSIONS:
        return
    for fname in sorted(os.listdir(BASE_DIR)):
        if fname.lower().endswith(".pdf"):
            sample_path = os.path.join(BASE_DIR, fname)
            if os.path.isfile(sample_path):
                doc_id = "sample-f1lcdx"
                SESSIONS[doc_id] = DocumentSession(doc_id, sample_path, fname)
                break


def _serialize_session(sess: DocumentSession) -> dict:
    matches_list = []
    for idx, m in enumerate(sess.matches):
        matches_list.append(
            {
                "index": idx,
                "enabled": idx not in sess.disabled_indices,
                "page_num": m.page_num,
                "category": m.category,
                "raw_value": m.raw_value,
                "canonical_key": m.canonical_key,
                "bbox": [round(v, 2) for v in m.bbox],
                "token": m.token,
            }
        )
    return {
        "doc_id": sess.doc_id,
        "filename": sess.filename,
        "page_count": sess.page_count,
        "page_sizes": sess.page_sizes,
        "patient_token_preview": sess.patient_token,
        "total_matches": len(sess.matches),
        "active_matches": len(sess.matches) - len(sess.disabled_indices),
        "matches": matches_list,
    }


@app.route("/")
def index():
    _autoload_sample()
    return render_template("index.html")


@app.route("/api/documents", methods=["GET"])
def api_list_documents():
    _autoload_sample()
    docs = [_serialize_session(s) for s in SESSIONS.values()]
    # Check if a vault already exists in OUTPUT_DIR
    default_vault = os.path.join(OUTPUT_DIR, "reid_key_vault.json")
    has_default_vault = os.path.isfile(default_vault)
    return jsonify({"documents": docs, "has_default_vault": has_default_vault})


@app.route("/api/upload", methods=["POST"])
def api_upload_pdfs():
    files = request.files.getlist("files")
    added = []
    for f in files:
        if not f.filename or not f.filename.lower().endswith(".pdf"):
            continue
        doc_id = f"doc-{uuid.uuid4().hex[:8]}"
        safe_name = os.path.basename(f.filename)
        save_path = os.path.join(UPLOAD_DIR, f"{doc_id}_{safe_name}")
        f.save(save_path)
        sess = DocumentSession(doc_id, save_path, safe_name)
        SESSIONS[doc_id] = sess
        added.append(_serialize_session(sess))
    return jsonify({"added": added, "documents": [_serialize_session(s) for s in SESSIONS.values()]})


@app.route("/api/documents/<doc_id>", methods=["DELETE"])
def api_delete_document(doc_id: str):
    SESSIONS.pop(doc_id, None)
    return jsonify({"documents": [_serialize_session(s) for s in SESSIONS.values()]})


@app.route("/api/documents/<doc_id>/page/<int:page_num>/image", methods=["GET"])
def api_page_image(doc_id: str, page_num: int):
    sess = SESSIONS.get(doc_id)
    if not sess or page_num < 0 or page_num >= sess.page_count:
        return ("Not found", 404)
    doc = pymupdf.open(sess.pdf_path)
    page = doc[page_num]
    pix = page.get_pixmap(matrix=pymupdf.Matrix(1.6, 1.6))
    img_bytes = pix.tobytes("png")
    doc.close()
    return send_file(io.BytesIO(img_bytes), mimetype="image/png")


@app.route("/api/documents/<doc_id>/toggle_match", methods=["POST"])
def api_toggle_match(doc_id: str):
    sess = SESSIONS.get(doc_id)
    if not sess:
        return jsonify({"error": "Document not found"}), 404
    data = request.get_json(force=True)
    idx = int(data.get("index", -1))
    if 0 <= idx < len(sess.matches):
        if idx in sess.disabled_indices:
            sess.disabled_indices.remove(idx)
        else:
            sess.disabled_indices.add(idx)
    return jsonify(_serialize_session(sess))


@app.route("/api/documents/<doc_id>/custom_phrase", methods=["POST"])
def api_add_custom_phrase(doc_id: str):
    sess = SESSIONS.get(doc_id)
    if not sess:
        return jsonify({"error": "Document not found"}), 404
    data = request.get_json(force=True)
    phrase = (data.get("phrase") or "").strip()
    category = (data.get("category") or "CUSTOM_PHI").strip()
    if not phrase:
        return jsonify({"error": "Phrase cannot be empty"}), 400

    added = 0
    for page_layout in sess.layouts:
        for seg in page_layout.segments:
            start = 0
            while True:
                pos = seg.text.find(phrase, start)
                if pos == -1:
                    break
                end = pos + len(phrase)
                bbox = seg.substring_bbox(pos, end)
                if bbox:
                    origin, size, color_int, font = seg.substring_style(pos, end)
                    orig_spans = seg.substring_original_spans(pos, end)
                    sess.matches.append(
                        PHIMatch(
                            page_num=seg.page_num,
                            category=category,
                            raw_value=phrase,
                            canonical_key=canonicalize_entity_key(category, phrase),
                            bbox=bbox,
                            origin=origin,
                            fontsize=size,
                            color_int=color_int,
                            font=font,
                            original_spans=orig_spans,
                        )
                    )
                    added += 1
                start = end

    preview_tok = BatchTokenizer(date_mode="mask", batch_salt="WEB-PREVIEW")
    preview_tok.assign_tokens(sess.matches, sess.filename)
    return jsonify({"added_count": added, "document": _serialize_session(sess)})


@app.route("/api/batch_deidentify", methods=["POST"])
def api_batch_deidentify():
    if not SESSIONS:
        return jsonify({"error": "No documents in queue"}), 400
    data = request.get_json(force=True) or {}
    date_mode = data.get("date_mode", "mask")
    password = (data.get("password") or "").strip() or None

    tokenizer = BatchTokenizer(date_mode=date_mode)
    vault_entries = []
    processed_files = []

    for sess in SESSIONS.values():
        active_matches = [
            m for idx, m in enumerate(sess.matches) if idx not in sess.disabled_indices
        ]
        out_pdf, entry, _ = deidentify_pdf_file(
            sess.pdf_path, OUTPUT_DIR, tokenizer, custom_matches=active_matches
        )
        vault_entries.append(entry)
        processed_files.append(
            {
                "doc_id": sess.doc_id,
                "original_filename": sess.filename,
                "deidentified_filename": entry.deidentified_filename,
                "patient_token": entry.patient_token,
                "redacted_count": len(active_matches),
                "entity_dictionary": entry.entity_dictionary,
            }
        )

    vault = ReIdVault(
        date_mode=date_mode,
        global_token_dictionary=tokenizer.global_token_to_original,
        documents=vault_entries,
    )
    vault_fname = "reid_key_vault.enc.json" if password else "reid_key_vault.json"
    vault_path = os.path.join(OUTPUT_DIR, vault_fname)
    save_vault(vault, vault_path, password=password)

    # Also keep unencrypted default vault updated if no password was used
    return jsonify(
        {
            "status": "ok",
            "date_mode": date_mode,
            "encrypted": bool(password),
            "vault_filename": vault_fname,
            "output_dir": OUTPUT_DIR,
            "processed_files": processed_files,
        }
    )


@app.route("/api/download/<path:filename>", methods=["GET"])
def api_download_output(filename: str):
    safe_name = os.path.basename(filename)
    target = os.path.join(OUTPUT_DIR, safe_name)
    if not os.path.isfile(target):
        return ("File not found", 404)
    return send_file(target, as_attachment=True, download_name=safe_name)


@app.route("/api/preview_output_pdf/<path:filename>/page/<int:page_num>", methods=["GET"])
def api_preview_output_pdf(filename: str, page_num: int):
    safe_name = os.path.basename(filename)
    target = os.path.join(OUTPUT_DIR, safe_name)
    if not os.path.isfile(target):
        return ("File not found", 404)
    doc = pymupdf.open(target)
    if page_num < 0 or page_num >= len(doc):
        page_num = 0
    pix = doc[page_num].get_pixmap(matrix=pymupdf.Matrix(1.5, 1.5))
    img_bytes = pix.tobytes("png")
    doc.close()
    return send_file(io.BytesIO(img_bytes), mimetype="image/png")


@app.route("/api/vault_inspect", methods=["POST"])
def api_vault_inspect():
    password = (request.form.get("password") or "").strip() or None
    vault_file = request.files.get("vault_file")

    try:
        if vault_file and vault_file.filename:
            tmp_vault = os.path.join(UPLOAD_DIR, f"vault_{uuid.uuid4().hex[:6]}.json")
            vault_file.save(tmp_vault)
            vault = load_vault(tmp_vault, password=password)
        else:
            default_vault = os.path.join(OUTPUT_DIR, "reid_key_vault.json")
            if not os.path.isfile(default_vault):
                return jsonify({"error": "No Re-ID Key Vault found. Run Batch De-Identification first or upload a vault file."}), 404
            vault = load_vault(default_vault, password=password)

        docs_summary = []
        for d in vault.documents:
            docs_summary.append(
                {
                    "patient_token": d.patient_token,
                    "original_filename": d.original_filename,
                    "deidentified_filename": d.deidentified_filename,
                    "original_sha256": d.original_sha256,
                    "deidentified_sha256": d.deidentified_sha256,
                    "redacted_regions": len(d.coordinate_records),
                    "entity_dictionary": d.entity_dictionary,
                }
            )
        return jsonify(
            {
                "schema_version": vault.schema_version,
                "created_at": vault.created_at,
                "date_mode": vault.date_mode,
                "documents": docs_summary,
            }
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/reverse", methods=["POST"])
def api_reverse():
    password = (request.form.get("password") or "").strip() or None
    vault_file = request.files.get("vault_file")
    target_file = request.files.get("target_file")
    cloud_text = request.form.get("cloud_text", "")
    preset_deid_filename = request.form.get("preset_deid_filename", "")

    try:
        if vault_file and vault_file.filename:
            tmp_vault = os.path.join(UPLOAD_DIR, f"rev_vault_{uuid.uuid4().hex[:6]}.json")
            vault_file.save(tmp_vault)
            vault = load_vault(tmp_vault, password=password)
        else:
            default_vault = os.path.join(OUTPUT_DIR, "reid_key_vault.json")
            if not os.path.isfile(default_vault):
                return jsonify({"error": "No Key Vault file provided or found in output_deidentified/."}), 400
            vault = load_vault(default_vault, password=password)

        # Case 1: Inline cloud text re-identification
        if cloud_text.strip() and not (target_file and target_file.filename) and not preset_deid_filename:
            reid_text, count = reidentify_text_content(cloud_text, vault)
            return jsonify(
                {
                    "mode": "text",
                    "replaced_count": count,
                    "reidentified_text": reid_text,
                }
            )

        # Case 2: Target file uploaded or preset output PDF selected
        if target_file and target_file.filename:
            safe_tname = os.path.basename(target_file.filename)
            target_path = os.path.join(UPLOAD_DIR, f"target_{uuid.uuid4().hex[:6]}_{safe_tname}")
            target_file.save(target_path)
        elif preset_deid_filename:
            safe_tname = os.path.basename(preset_deid_filename)
            target_path = os.path.join(OUTPUT_DIR, safe_tname)
            if not os.path.isfile(target_path):
                return jsonify({"error": f"Preset file '{safe_tname}' not found in output_deidentified/."}), 404
        else:
            return jsonify({"error": "Please select a De-Identified PDF, upload a Cloud Analysis file, or paste cloud text."}), 400

        ext = os.path.splitext(target_path)[1].lower()
        if ext == ".pdf":
            entry_out_name = f"RESTORED_{safe_tname.replace('DEID_', '')}"
            out_pdf_path = os.path.join(OUTPUT_DIR, entry_out_name)
            restored_path, count = reverse_deidentified_pdf(target_path, vault, out_pdf_path)
            doc = pymupdf.open(restored_path)
            page_count = len(doc)
            p1_text = doc[0].get_text("text")
            doc.close()
            return jsonify(
                {
                    "mode": "pdf",
                    "restored_filename": os.path.basename(restored_path),
                    "restored_count": count,
                    "page_count": page_count,
                    "sample_text": p1_text,
                }
            )
        else:
            out_name = f"REIDENTIFIED_{safe_tname}"
            out_path = os.path.join(OUTPUT_DIR, out_name)
            _, count = reidentify_cloud_file(target_path, vault, out_path)
            with open(out_path, "r", encoding="utf-8") as f:
                reid_text = f.read()
            return jsonify(
                {
                    "mode": "cloud_file",
                    "reidentified_filename": out_name,
                    "replaced_count": count,
                    "reidentified_text": reid_text,
                }
            )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


if __name__ == "__main__":
    _autoload_sample()
    url = "http://127.0.0.1:5050"
    print("=" * 72)
    print(f"HIPAA Safe Harbor Local Web App running at: {url}")
    print("=" * 72)
    if "--open-browser" in sys.argv or getattr(sys, "frozen", False):
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=5050, debug=False)
