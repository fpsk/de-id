#!/usr/bin/env python3
"""
Cross-Platform Desktop GUI (macOS & Windows) for the Non-LLM HIPAA Safe Harbor
PDF De-Identification & Re-Identification Suite.

Launch with:
    python3 app.py
"""

import csv
import io
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Dict, List, Optional
from PIL import Image, ImageDraw, ImageTk
import pymupdf

from deid_engine.pdf_redactor import deidentify_pdf_file
from deid_engine.phi_detector import PHIMatch, canonicalize_entity_key, detect_phi_in_document
from deid_engine.reverser import reidentify_cloud_file, reverse_deidentified_pdf
from deid_engine.spatial_parser import PageLayout, parse_page_layout
from deid_engine.tokenizer import BatchTokenizer
from deid_engine.vault import ReIdVault, load_vault, save_vault


CATEGORY_COLORS = {
    "PATIENT_NAME": "#E53935",     # Red
    "DOB": "#FB8C00",              # Orange
    "MRN": "#8E24AA",              # Purple
    "ORDER_ID": "#1E88E5",         # Blue
    "SPECIMEN_ID": "#00897B",      # Teal
    "PHYSICIAN": "#3949AB",        # Indigo
    "FACILITY": "#43A047",         # Green
    "FACILITY_ID": "#2E7D32",      # Dark Green
    "REPORT_DATE": "#F4511E",      # Deep Orange
    "COLLECTION_DATE": "#FB8C00",  # Orange
    "RECEIVED_DATE": "#FFA000",    # Amber
    "DATE": "#F57C00",             # Orange
}


class DeIdDesktopApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("HIPAA Safe Harbor PDF De-Identification & Reversal Suite (Local Non-LLM)")
        self.geometry("1360x860")
        self.minsize(1100, 720)

        # State for Tab 1 (Batch De-Identification)
        self.pdf_queue: List[str] = []
        self.doc_matches_cache: Dict[str, List[PHIMatch]] = {}
        self.doc_disabled_indices: Dict[str, set] = {}
        self.doc_layouts_cache: Dict[str, List[PageLayout]] = {}

        self.current_pdf_path: Optional[str] = None
        self.current_page_idx: int = 0
        self.current_total_pages: int = 0
        self.preview_photo: Optional[ImageTk.PhotoImage] = None

        self.output_dir_var = tk.StringVar(
            value=os.path.join(os.getcwd(), "output_deidentified")
        )
        self.date_mode_var = tk.StringVar(value="mask")
        self.vault_password_var = tk.StringVar(value="")

        # State for Tab 2 (Reversal / Cloud Re-Identification)
        self.rev_vault_path_var = tk.StringVar(value="")
        self.rev_target_path_var = tk.StringVar(value="")
        self.rev_password_var = tk.StringVar(value="")
        self.rev_preview_photo: Optional[ImageTk.PhotoImage] = None

        # State for Tab 3 (Vault Inspector)
        self.loaded_vault: Optional[ReIdVault] = None

        self._build_ui()
        self._autoload_workspace_sample()

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Header.TLabel", font=("Helvetica", 13, "bold"))
        style.configure("Subheader.TLabel", font=("Helvetica", 10, "bold"))
        style.configure("Primary.TButton", font=("Helvetica", 10, "bold"), padding=6)

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.tab_deid = ttk.Frame(notebook)
        self.tab_reverse = ttk.Frame(notebook)
        self.tab_vault = ttk.Frame(notebook)

        notebook.add(self.tab_deid, text="  1. Batch De-Identify & Visual Preview  ")
        notebook.add(self.tab_reverse, text="  2. Reverse PDF / Re-Identify Cloud Results  ")
        notebook.add(self.tab_vault, text="  3. Key Vault Inspector & Audit  ")

        self._build_tab_deid()
        self._build_tab_reverse()
        self._build_tab_vault()

    # =========================================================================
    # TAB 1: Batch De-Identify & Interactive Preview
    # =========================================================================
    def _build_tab_deid(self) -> None:
        top_bar = ttk.LabelFrame(self.tab_deid, text="Batch Input & HIPAA Safe Harbor Settings", padding=8)
        top_bar.pack(fill=tk.X, padx=8, pady=6)

        btn_frame = ttk.Frame(top_bar)
        btn_frame.pack(fill=tk.X, pady=2)

        ttk.Button(btn_frame, text="+ Add PDF File(s)", command=self._add_pdf_files).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="+ Add Folder of PDFs", command=self._add_pdf_folder).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="- Remove Selected", command=self._remove_selected_pdf).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Clear Queue", command=self._clear_queue).pack(side=tk.LEFT, padx=4)

        ttk.Separator(btn_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        ttk.Label(btn_frame, text="Date Mode:").pack(side=tk.LEFT, padx=4)
        date_combo = ttk.Combobox(
            btn_frame,
            textvariable=self.date_mode_var,
            values=["mask", "shift"],
            width=10,
            state="readonly",
        )
        date_combo.pack(side=tk.LEFT, padx=4)

        ttk.Label(btn_frame, text="Vault Password (Optional AES-256):").pack(side=tk.LEFT, padx=8)
        ttk.Entry(btn_frame, textvariable=self.vault_password_var, show="*", width=16).pack(side=tk.LEFT, padx=4)

        out_frame = ttk.Frame(top_bar)
        out_frame.pack(fill=tk.X, pady=4)
        ttk.Label(out_frame, text="Output Folder:").pack(side=tk.LEFT, padx=4)
        ttk.Entry(out_frame, textvariable=self.output_dir_var, width=65).pack(side=tk.LEFT, padx=4, fill=tk.X, expand=True)
        ttk.Button(out_frame, text="Browse...", command=self._browse_output_dir).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            out_frame,
            text="Run Batch De-Identification & Generate Key Vault",
            style="Primary.TButton",
            command=self._run_batch_deidentification,
        ).pack(side=tk.RIGHT, padx=6)

        # Main 3-Pane Split: Left (PDF Queue) | Center (Visual PDF Page Preview) | Right (Detected PHI Table)
        paned = ttk.PanedWindow(self.tab_deid, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # Left Pane: PDF Batch Queue
        left_frame = ttk.LabelFrame(paned, text="PDF Batch Queue", padding=6)
        paned.add(left_frame, weight=1)

        self.queue_listbox = tk.Listbox(left_frame, selectmode=tk.SINGLE, font=("Helvetica", 10))
        self.queue_listbox.pack(fill=tk.BOTH, expand=True)
        self.queue_listbox.bind("<<ListboxSelect>>", self._on_select_pdf_in_queue)

        # Center Pane: Visual Page Canvas with PHI Highlight Overlays
        center_frame = ttk.LabelFrame(paned, text="Interactive Page Preview (PHI Highlighted)", padding=6)
        paned.add(center_frame, weight=3)

        nav_bar = ttk.Frame(center_frame)
        nav_bar.pack(fill=tk.X, pady=2)
        ttk.Button(nav_bar, text="◀ Prev Page", command=self._prev_page).pack(side=tk.LEFT, padx=4)
        self.page_label = ttk.Label(nav_bar, text="Page 0 / 0", style="Subheader.TLabel")
        self.page_label.pack(side=tk.LEFT, padx=10)
        ttk.Button(nav_bar, text="Next Page ▶", command=self._next_page).pack(side=tk.LEFT, padx=4)

        self.summary_badge = ttk.Label(nav_bar, text="")
        self.summary_badge.pack(side=tk.RIGHT, padx=6)

        canvas_container = ttk.Frame(center_frame)
        canvas_container.pack(fill=tk.BOTH, expand=True)

        self.preview_canvas = tk.Canvas(canvas_container, bg="#2B2B2B", highlightthickness=0)
        v_scroll = ttk.Scrollbar(canvas_container, orient=tk.VERTICAL, command=self.preview_canvas.yview)
        h_scroll = ttk.Scrollbar(canvas_container, orient=tk.HORIZONTAL, command=self.preview_canvas.xview)
        self.preview_canvas.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.preview_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Right Pane: Detected PHI Table & Custom Redaction Controls
        right_frame = ttk.LabelFrame(paned, text="Detected PHI Entities (Double-Click to Toggle On/Off)", padding=6)
        paned.add(right_frame, weight=2)

        right_Readout = ttk.Frame(right_frame)
        right_Readout.pack(fill=tk.X, pady=2)
        ttk.Button(right_Readout, text="+ Add Custom Phrase to Redact", command=self._add_custom_phrase).pack(side=tk.LEFT, padx=2)
        ttk.Button(right_Readout, text="Toggle Selected Item", command=self._toggle_selected_phi).pack(side=tk.LEFT, padx=4)

        cols = ("status", "page", "category", "value", "token")
        self.phi_tree = ttk.Treeview(right_frame, columns=cols, show="headings", selectmode="browse")
        self.phi_tree.heading("status", text="Redact?")
        self.phi_tree.heading("page", text="Page")
        self.phi_tree.heading("category", text="Category")
        self.phi_tree.heading("value", text="Original PHI Value")
        self.phi_tree.heading("token", text="Preview Token")

        self.phi_tree.column("status", width=60, anchor=tk.CENTER)
        self.phi_tree.column("page", width=48, anchor=tk.CENTER)
        self.phi_tree.column("category", width=105, anchor=tk.W)
        self.phi_tree.column("value", width=165, anchor=tk.W)
        self.phi_tree.column("token", width=120, anchor=tk.W)

        tree_scroll = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.phi_tree.yview)
        self.phi_tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.phi_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.phi_tree.bind("<Double-1>", lambda _e: self._toggle_selected_phi())
        self.phi_tree.bind("<<TreeviewSelect>>", self._on_select_phi_row)

    # =========================================================================
    # TAB 2: Reverse PDF & Re-Identify Cloud Output
    # =========================================================================
    def _build_tab_reverse(self) -> None:
        top_box = ttk.LabelFrame(
            self.tab_reverse,
            text="Combine Re-Identification Key Vault + De-Identified PDF or Cloud Analysis File",
            padding=10,
        )
        top_box.pack(fill=tk.X, padx=10, pady=8)

        row1 = ttk.Frame(top_box)
        row1.pack(fill=tk.X, pady=4)
        ttk.Label(row1, text="1. Re-ID Key Vault File (.json):", width=30).pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.rev_vault_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(row1, text="Browse Vault...", command=self._browse_rev_vault).pack(side=tk.LEFT, padx=4)

        row2 = ttk.Frame(top_box)
        row2.pack(fill=tk.X, pady=4)
        ttk.Label(row2, text="2. De-Identified PDF / Cloud File:", width=30).pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.rev_target_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(row2, text="Browse Target File...", command=self._browse_rev_target).pack(side=tk.LEFT, padx=4)

        row3 = ttk.Frame(top_box)
        row3.pack(fill=tk.X, pady=4)
        ttk.Label(row3, text="3. Vault Password (if encrypted):", width=30).pack(side=tk.LEFT)
        ttk.Entry(row3, textvariable=self.rev_password_var, show="*", width=24).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            row3,
            text="Combine & Reverse / Re-Identify Now",
            style="Primary.TButton",
            command=self._run_reversal,
        ).pack(side=tk.RIGHT, padx=6)

        split = ttk.PanedWindow(self.tab_reverse, orient=tk.HORIZONTAL)
        split.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        left_rev = ttk.LabelFrame(split, text="Restored PDF Visual Preview", padding=6)
        split.add(left_rev, weight=1)
        self.rev_canvas = tk.Canvas(left_rev, bg="#2B2B2B", highlightthickness=0)
        self.rev_canvas.pack(fill=tk.BOTH, expand=True)

        right_rev = ttk.LabelFrame(split, text="Reversal Log & Re-Identified Cloud Text Output", padding=6)
        split.add(right_rev, weight=1)
        self.rev_text = tk.Text(right_rev, font=("Menlo", 11), wrap=tk.WORD)
        self.rev_text.pack(fill=tk.BOTH, expand=True)

    # =========================================================================
    # TAB 3: Vault Inspector & Audit
    # =========================================================================
    def _build_tab_vault(self) -> None:
        bar = ttk.Frame(self.tab_vault, padding=8)
        bar.pack(fill=tk.X)
        ttk.Button(bar, text="Load Re-ID Key Vault (.json)...", command=self._load_vault_for_inspector).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Export Crosswalk Table to CSV...", command=self._export_vault_csv).pack(side=tk.LEFT, padx=4)
        self.vault_info_label = ttk.Label(bar, text="No vault loaded", style="Subheader.TLabel")
        self.vault_info_label.pack(side=tk.LEFT, padx=16)

        cols = ("patient_token", "token", "original_value", "source_file", "deid_file")
        self.vault_tree = ttk.Treeview(self.tab_vault, columns=cols, show="headings")
        self.vault_tree.heading("patient_token", text="Patient Token")
        self.vault_tree.heading("token", text="Pseudonym Token")
        self.vault_tree.heading("original_value", text="Original PHI Value(s)")
        self.vault_tree.heading("source_file", text="Original PDF Filename")
        self.vault_tree.heading("deid_file", text="De-Identified PDF Filename")

        self.vault_tree.column("patient_token", width=120)
        self.vault_tree.column("token", width=150)
        self.vault_tree.column("original_value", width=340)
        self.vault_tree.column("source_file", width=320)
        self.vault_tree.column("deid_file", width=260)

        self.vault_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

    # =========================================================================
    # Helper Logic & Event Handlers
    # =========================================================================
    def _autoload_workspace_sample(self) -> None:
        for fname in sorted(os.listdir(os.getcwd())):
            if fname.lower().endswith(".pdf"):
                sample = os.path.join(os.getcwd(), fname)
                if os.path.isfile(sample):
                    self._enqueue_pdf(sample)
                    self.queue_listbox.selection_set(0)
                    self._load_pdf_for_preview(sample)
                    break

        # Also pre-populate Tab 2 if output_deidentified exists
        vault_cand = os.path.join(os.getcwd(), "output_deidentified", "reid_key_vault.json")
        if os.path.isfile(vault_cand):
            self.rev_vault_path_var.set(vault_cand)
            self._populate_vault_inspector(vault_cand)

    def _enqueue_pdf(self, path: str) -> None:
        abspath = os.path.abspath(path)
        if abspath not in self.pdf_queue:
            self.pdf_queue.append(abspath)
            self.queue_listbox.insert(tk.END, os.path.basename(abspath))

    def _add_pdf_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select PDF Files to De-Identify",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
        )
        for p in paths:
            self._enqueue_pdf(p)
        if self.pdf_queue and self.current_pdf_path is None:
            self.queue_listbox.selection_set(0)
            self._load_pdf_for_preview(self.pdf_queue[0])

    def _add_pdf_folder(self) -> None:
        folder = filedialog.askdirectory(title="Select Folder Containing PDF Files")
        if not folder:
            return
        added = 0
        for root, _, files in os.walk(folder):
            for f in sorted(files):
                if f.lower().endswith(".pdf") and not f.startswith(("DEID_", "RESTORED_")):
                    self._enqueue_pdf(os.path.join(root, f))
                    added += 1
        messagebox.showinfo("Folder Scanned", f"Added {added} PDF file(s) to the batch queue.")
        if self.pdf_queue and self.current_pdf_path is None:
            self.queue_listbox.selection_set(0)
            self._load_pdf_for_preview(self.pdf_queue[0])

    def _remove_selected_pdf(self) -> None:
        sel = self.queue_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        self.queue_listbox.delete(idx)
        removed = self.pdf_queue.pop(idx)
        if self.current_pdf_path == removed:
            self.current_pdf_path = None
            self.preview_canvas.delete("all")
            self.phi_tree.delete(*self.phi_tree.get_children())

    def _clear_queue(self) -> None:
        self.pdf_queue.clear()
        self.queue_listbox.delete(0, tk.END)
        self.current_pdf_path = None
        self.preview_canvas.delete("all")
        self.phi_tree.delete(*self.phi_tree.get_children())

    def _browse_output_dir(self) -> None:
        d = filedialog.askdirectory(title="Select Output Directory")
        if d:
            self.output_dir_var.set(d)

    def _on_select_pdf_in_queue(self, _event: object) -> None:
        sel = self.queue_listbox.curselection()
        if not sel:
            return
        pdf_path = self.pdf_queue[sel[0]]
        if pdf_path != self.current_pdf_path:
            self._load_pdf_for_preview(pdf_path)

    def _ensure_pdf_analyzed(self, pdf_path: str) -> List[PHIMatch]:
        if pdf_path not in self.doc_matches_cache:
            doc = pymupdf.open(pdf_path)
            layouts = [parse_page_layout(doc[i], i) for i in range(len(doc))]
            doc.close()
            self.doc_layouts_cache[pdf_path] = layouts
            matches = detect_phi_in_document(layouts, filename=os.path.basename(pdf_path))
            # Preview token assignment
            preview_tok = BatchTokenizer(date_mode=self.date_mode_var.get(), batch_salt="PREVIEW")
            preview_tok.assign_tokens(matches, os.path.basename(pdf_path))
            self.doc_matches_cache[pdf_path] = matches
            self.doc_disabled_indices[pdf_path] = set()
        return self.doc_matches_cache[pdf_path]

    def _load_pdf_for_preview(self, pdf_path: str) -> None:
        self.current_pdf_path = pdf_path
        matches = self._ensure_pdf_analyzed(pdf_path)
        doc = pymupdf.open(pdf_path)
        self.current_total_pages = len(doc)
        doc.close()
        self.current_page_idx = 0
        self._refresh_phi_tree()
        self._render_current_page()

    def _refresh_phi_tree(self) -> None:
        self.phi_tree.delete(*self.phi_tree.get_children())
        if not self.current_pdf_path:
            return
        matches = self.doc_matches_cache.get(self.current_pdf_path, [])
        disabled = self.doc_disabled_indices.get(self.current_pdf_path, set())

        active_count = len(matches) - len(disabled)
        self.summary_badge.configure(
            text=f"Active Redactions: {active_count} / {len(matches)} across {self.current_total_pages} pages"
        )

        for idx, m in enumerate(matches):
            status_str = "YES" if idx not in disabled else "SKIP"
            self.phi_tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(status_str, m.page_num + 1, m.category, m.raw_value, m.token),
            )

    def _render_current_page(self) -> None:
        if not self.current_pdf_path:
            return
        doc = pymupdf.open(self.current_pdf_path)
        if self.current_page_idx >= len(doc):
            self.current_page_idx = 0
        page = doc[self.current_page_idx]
        zoom = 1.35
        pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))
        doc.close()

        img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGBA")
        overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(overlay)

        matches = self.doc_matches_cache.get(self.current_pdf_path, [])
        disabled = self.doc_disabled_indices.get(self.current_pdf_path, set())

        for idx, m in enumerate(matches):
            if m.page_num != self.current_page_idx:
                continue
            x0, y0, x1, y1 = [v * zoom for v in m.bbox]
            if idx in disabled:
                draw.rectangle([x0, y0, x1, y1], outline=(160, 160, 160, 200), width=1)
            else:
                hex_col = CATEGORY_COLORS.get(m.category, "#E53935").lstrip("#")
                r, g, b = int(hex_col[0:2], 16), int(hex_col[2:4], 16), int(hex_col[4:6], 16)
                draw.rectangle([x0, y0, x1, y1], fill=(r, g, b, 55), outline=(r, g, b, 235), width=2)

        combined = Image.alpha_composite(img, overlay).convert("RGB")
        self.preview_photo = ImageTk.PhotoImage(combined)
        self.preview_canvas.delete("all")
        self.preview_canvas.create_image(10, 10, anchor=tk.NW, image=self.preview_photo)
        self.preview_canvas.configure(scrollregion=(0, 0, combined.width + 20, combined.height + 20))
        self.page_label.configure(text=f"Page {self.current_page_idx + 1} / {self.current_total_pages}")

    def _prev_page(self) -> None:
        if self.current_pdf_path and self.current_page_idx > 0:
            self.current_page_idx -= 1
            self._render_current_page()

    def _next_page(self) -> None:
        if self.current_pdf_path and self.current_page_idx + 1 < self.current_total_pages:
            self.current_page_idx += 1
            self._render_current_page()

    def _on_select_phi_row(self, _event: object) -> None:
        sel = self.phi_tree.selection()
        if not sel or not self.current_pdf_path:
            return
        idx = int(sel[0])
        matches = self.doc_matches_cache.get(self.current_pdf_path, [])
        if 0 <= idx < len(matches):
            target_page = matches[idx].page_num
            if target_page != self.current_page_idx:
                self.current_page_idx = target_page
                self._render_current_page()

    def _toggle_selected_phi(self) -> None:
        sel = self.phi_tree.selection()
        if not sel or not self.current_pdf_path:
            return
        idx = int(sel[0])
        disabled = self.doc_disabled_indices.setdefault(self.current_pdf_path, set())
        if idx in disabled:
            disabled.remove(idx)
        else:
            disabled.add(idx)
        self._refresh_phi_tree()
        self.phi_tree.selection_set(str(idx))
        self._render_current_page()

    def _add_custom_phrase(self) -> None:
        if not self.current_pdf_path:
            return
        phrase = simpledialog.askstring(
            "Add Custom Redaction Phrase",
            "Enter exact text/ID/name to redact across all pages of this PDF:",
            parent=self,
        )
        if not phrase or not phrase.strip():
            return
        phrase = phrase.strip()
        layouts = self.doc_layouts_cache.get(self.current_pdf_path, [])
        matches = self.doc_matches_cache.get(self.current_pdf_path, [])
        added = 0
        for page_layout in layouts:
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
                        matches.append(
                            PHIMatch(
                                page_num=seg.page_num,
                                category="CUSTOM_PHI",
                                raw_value=phrase,
                                canonical_key=canonicalize_entity_key("CUSTOM_PHI", phrase),
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

        preview_tok = BatchTokenizer(date_mode=self.date_mode_var.get(), batch_salt="PREVIEW")
        preview_tok.assign_tokens(matches, os.path.basename(self.current_pdf_path))
        self._refresh_phi_tree()
        self._render_current_page()
        messagebox.showinfo("Custom Phrase Added", f"Found and marked {added} occurrence(s) of '{phrase}'.")

    def _run_batch_deidentification(self) -> None:
        if not self.pdf_queue:
            messagebox.showwarning("Empty Queue", "Please add at least one PDF file to the batch queue.")
            return

        out_dir = self.output_dir_var.get().strip() or os.path.join(os.getcwd(), "output_deidentified")
        os.makedirs(out_dir, exist_ok=True)
        date_mode = self.date_mode_var.get()
        password = self.vault_password_var.get().strip() or None

        tokenizer = BatchTokenizer(date_mode=date_mode)
        vault_entries = []
        last_deid_pdf = None

        for pdf_path in self.pdf_queue:
            all_matches = self._ensure_pdf_analyzed(pdf_path)
            disabled = self.doc_disabled_indices.get(pdf_path, set())
            active_matches = [m for i, m in enumerate(all_matches) if i not in disabled]
            out_pdf, entry, _ = deidentify_pdf_file(
                pdf_path, out_dir, tokenizer, custom_matches=active_matches
            )
            vault_entries.append(entry)
            last_deid_pdf = out_pdf

        vault = ReIdVault(
            date_mode=date_mode,
            global_token_dictionary=tokenizer.global_token_to_original,
            documents=vault_entries,
        )
        vault_fname = "reid_key_vault.enc.json" if password else "reid_key_vault.json"
        vault_path = os.path.join(out_dir, vault_fname)
        save_vault(vault, vault_path, password=password)

        # Auto-populate Tab 2 & Tab 3 for immediate testing
        self.rev_vault_path_var.set(vault_path)
        if last_deid_pdf:
            self.rev_target_path_var.set(last_deid_pdf)
        if password:
            self.rev_password_var.set(password)
        self._populate_vault_inspector(vault_path, password=password)

        messagebox.showinfo(
            "Batch De-Identification Complete",
            f"Successfully processed {len(vault_entries)} PDF file(s)!\n\n"
            f"Output Folder:\n{out_dir}\n\n"
            f"Re-Identification Key Vault:\n{vault_path}",
        )

    # =========================================================================
    # TAB 2 Handlers: Reverse PDF / Re-Identify Cloud Output
    # =========================================================================
    def _browse_rev_vault(self) -> None:
        p = filedialog.askopenfilename(
            title="Select Re-Identification Key Vault (.json)",
            filetypes=[("JSON Key Vault", "*.json"), ("All files", "*.*")],
        )
        if p:
            self.rev_vault_path_var.set(p)

    def _browse_rev_target(self) -> None:
        p = filedialog.askopenfilename(
            title="Select De-Identified PDF or Cloud Analysis File",
            filetypes=[
                ("Supported Files", "*.pdf *.csv *.json *.md *.txt *.tsv *.html"),
                ("All files", "*.*"),
            ],
        )
        if p:
            self.rev_target_path_var.set(p)

    def _run_reversal(self) -> None:
        vault_path = self.rev_vault_path_var.get().strip()
        target_path = self.rev_target_path_var.get().strip()
        password = self.rev_password_var.get().strip() or None

        if not os.path.isfile(vault_path):
            messagebox.showerror("Missing Key Vault", "Please select a valid Re-ID Key Vault (.json) file.")
            return
        if not os.path.isfile(target_path):
            messagebox.showerror("Missing Target File", "Please select a De-Identified PDF or Cloud file to reverse.")
            return

        try:
            vault = load_vault(vault_path, password=password)
            ext = os.path.splitext(target_path)[1].lower()
            if ext == ".pdf":
                restored_pdf, count = reverse_deidentified_pdf(target_path, vault)
                doc = pymupdf.open(restored_pdf)
                pix = doc[0].get_pixmap(matrix=pymupdf.Matrix(1.1, 1.1))
                p1_text = doc[0].get_text("text")
                doc.close()

                img = Image.open(io.BytesIO(pix.tobytes("png")))
                self.rev_preview_photo = ImageTk.PhotoImage(img)
                self.rev_canvas.delete("all")
                self.rev_canvas.create_image(10, 10, anchor=tk.NW, image=self.rev_preview_photo)

                self.rev_text.delete("1.0", tk.END)
                self.rev_text.insert(
                    tk.END,
                    f"=== PDF REVERSAL SUCCESSFUL ===\n"
                    f"Restored Regions : {count}\n"
                    f"Restored File    : {restored_pdf}\n\n"
                    f"--- Restored Page 1 Text Sample ---\n{p1_text}\n",
                )
                messagebox.showinfo(
                    "PDF Reversed Successfully",
                    f"Restored {count} PHI spans!\n\nSaved Restored PDF to:\n{restored_pdf}",
                )
            else:
                out_file, count = reidentify_cloud_file(target_path, vault)
                with open(out_file, "r", encoding="utf-8") as f:
                    reid_text = f.read()
                self.rev_text.delete("1.0", tk.END)
                self.rev_text.insert(
                    tk.END,
                    f"=== CLOUD FILE RE-IDENTIFICATION SUCCESSFUL ===\n"
                    f"Replaced Tokens  : {count}\n"
                    f"Saved Output To  : {out_file}\n\n"
                    f"--- Re-Identified Content ---\n{reid_text}\n",
                )
                messagebox.showinfo(
                    "Cloud File Re-Identified",
                    f"Re-identified {count} pseudonym token(s)!\n\nSaved to:\n{out_file}",
                )
        except Exception as exc:
            messagebox.showerror("Reversal Error", str(exc))

    # =========================================================================
    # TAB 3 Handlers: Vault Inspector & CSV Export
    # =========================================================================
    def _load_vault_for_inspector(self) -> None:
        p = filedialog.askopenfilename(
            title="Select Re-ID Key Vault (.json)",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not p:
            return
        pw = self.vault_password_var.get().strip() or None
        try:
            self._populate_vault_inspector(p, password=pw)
        except ValueError:
            pw = simpledialog.askstring("Password Required", "Enter password for encrypted Key Vault:", show="*")
            if pw:
                self._populate_vault_inspector(p, password=pw)

    def _populate_vault_inspector(self, vault_path: str, password: Optional[str] = None) -> None:
        vault = load_vault(vault_path, password=password)
        self.loaded_vault = vault
        self.vault_tree.delete(*self.vault_tree.get_children())
        self.vault_info_label.configure(
            text=f"Loaded Vault: {os.path.basename(vault_path)} | {len(vault.documents)} Document(s) | Date Mode: {vault.date_mode}"
        )
        for doc in vault.documents:
            for tok, orig in doc.entity_dictionary.items():
                self.vault_tree.insert(
                    "",
                    tk.END,
                    values=(
                        doc.patient_token,
                        tok,
                        orig,
                        doc.original_filename,
                        doc.deidentified_filename,
                    ),
                )

    def _export_vault_csv(self) -> None:
        if not self.loaded_vault:
            messagebox.showwarning("No Vault Loaded", "Please load a Re-ID Key Vault first.")
            return
        out_csv = filedialog.asksaveasfilename(
            title="Export Crosswalk CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
        )
        if not out_csv:
            return
        with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Patient_Token", "Pseudonym_Token", "Original_PHI_Value", "Original_Filename", "DeIdentified_Filename"]
            )
            for doc in self.loaded_vault.documents:
                for tok, orig in doc.entity_dictionary.items():
                    writer.writerow([doc.patient_token, tok, orig, doc.original_filename, doc.deidentified_filename])
        messagebox.showinfo("Exported CSV", f"Crosswalk table exported to:\n{out_csv}")


if __name__ == "__main__":
    app = DeIdDesktopApp()
    app.mainloop()
