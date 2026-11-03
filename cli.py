#!/usr/bin/env python3
"""
Command-Line Interface for the HIPAA Safe Harbor Non-LLM PDF De-Identification & Reversal Suite.

Examples:
  # 1. Batch de-identify one or more PDFs or a folder of PDFs:
  python3 cli.py deidentify "./sample_report.pdf" -o ./output_deidentified

  # 2. Reverse a de-identified PDF back to the original PDF using the Key Vault:
  python3 cli.py reverse output_deidentified/DEID_PAT-1D7030_ORD-1D7030-01.pdf -k output_deidentified/reid_key_vault.json

  # 3. Re-identify a cloud analysis result (.csv, .json, .md, .txt) using the Key Vault:
  python3 cli.py reidentify cloud_results.md -k output_deidentified/reid_key_vault.json

  # 4. Inspect a Re-ID Key Vault:
  python3 cli.py inspect output_deidentified/reid_key_vault.json
"""

import argparse
import glob
import os
import sys
from typing import List

from deid_engine.pdf_redactor import deidentify_pdf_file
from deid_engine.reverser import reidentify_cloud_file, reverse_deidentified_pdf
from deid_engine.tokenizer import BatchTokenizer
from deid_engine.vault import ReIdVault, load_vault, save_vault


def _collect_pdf_paths(inputs: List[str]) -> List[str]:
    pdf_paths: List[str] = []
    for item in inputs:
        if os.path.isdir(item):
            for root, _, files in os.walk(item):
                for f in sorted(files):
                    if f.lower().endswith(".pdf") and not f.startswith(("DEID_", "RESTORED_")):
                        pdf_paths.append(os.path.join(root, f))
        elif os.path.isfile(item) and item.lower().endswith(".pdf"):
            pdf_paths.append(item)
        else:
            for matched in sorted(glob.glob(item)):
                if os.path.isfile(matched) and matched.lower().endswith(".pdf"):
                    pdf_paths.append(matched)
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for p in pdf_paths:
        ap = os.path.abspath(p)
        if ap not in seen:
            seen.add(ap)
            unique.append(ap)
    return unique


def cmd_deidentify(args: argparse.Namespace) -> None:
    pdf_files = _collect_pdf_paths(args.inputs)
    if not pdf_files:
        print("Error: No input PDF files found.", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    tokenizer = BatchTokenizer(date_mode=args.date_mode, batch_salt=args.salt)
    vault_entries = []

    print(f"Processing batch of {len(pdf_files)} PDF file(s) [Date Mode: {args.date_mode}]...")
    for idx, pdf_path in enumerate(pdf_files, start=1):
        out_pdf, entry, matches = deidentify_pdf_file(pdf_path, args.output_dir, tokenizer)
        vault_entries.append(entry)
        print(
            f"  [{idx}/{len(pdf_files)}] {os.path.basename(pdf_path)}\n"
            f"        -> De-Identified PDF : {out_pdf}\n"
            f"        -> Patient Token     : {entry.patient_token} ({len(matches)} PHI regions scrubbed)"
        )

    vault = ReIdVault(
        date_mode=args.date_mode,
        global_token_dictionary=tokenizer.global_token_to_original,
        documents=vault_entries,
    )
    vault_filename = args.vault_name or ("reid_key_vault.enc.json" if args.password else "reid_key_vault.json")
    vault_path = os.path.join(args.output_dir, vault_filename)
    save_vault(vault, vault_path, password=args.password)
    print(f"\nSuccess! Re-Identification Key Vault saved to: {vault_path}")


def cmd_reverse(args: argparse.Namespace) -> None:
    vault = load_vault(args.key_vault, password=args.password)
    restored_path, count = reverse_deidentified_pdf(args.pdf, vault, args.output)
    print(f"Restored {count} PHI regions -> Saved reversed PDF to: {restored_path}")


def cmd_reidentify(args: argparse.Namespace) -> None:
    vault = load_vault(args.key_vault, password=args.password)
    out_path, count = reidentify_cloud_file(args.input_file, vault, args.output)
    print(f"Re-identified {count} pseudonym token(s) -> Saved output to: {out_path}")


def cmd_inspect(args: argparse.Namespace) -> None:
    vault = load_vault(args.key_vault, password=args.password)
    print(f"Vault Schema Version : {vault.schema_version}")
    print(f"Created At           : {vault.created_at}")
    print(f"Date Mode            : {vault.date_mode}")
    print(f"Documents in Vault   : {len(vault.documents)}")
    for idx, doc in enumerate(vault.documents, start=1):
        print(f"\n--- Document {idx}: {doc.patient_token} ---")
        print(f"  Original File      : {doc.original_filename}")
        print(f"  De-Identified File : {doc.deidentified_filename}")
        print(f"  Redacted Regions   : {len(doc.coordinate_records)}")
        print("  Token Mappings:")
        for tok, orig in doc.entity_dictionary.items():
            print(f"    {tok:18s} -> {orig}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HIPAA Safe Harbor Non-LLM PDF De-Identification & Reversal CLI"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # deidentify
    p_deid = sub.add_parser("deidentify", help="Batch de-identify PDF files or folders")
    p_deid.add_argument("inputs", nargs="+", help="Input PDF file(s) or folder(s)")
    p_deid.add_argument("-o", "--output-dir", default="./output_deidentified", help="Output folder")
    p_deid.add_argument(
        "--date-mode",
        choices=["mask", "shift"],
        default="mask",
        help="Date handling mode: 'mask' (YYYY-XX-XX / YYYY-DATE-NN) or 'shift' (consistent day offset)",
    )
    p_deid.add_argument("--password", default=None, help="Optional password to AES-encrypt the Key Vault")
    p_deid.add_argument("--salt", default=None, help="Optional batch salt for deterministic tokens")
    p_deid.add_argument("--vault-name", default=None, help="Custom filename for the Key Vault")
    p_deid.set_defaults(func=cmd_deidentify)

    # reverse
    p_rev = sub.add_parser("reverse", help="Combine Key Vault + De-Identified PDF to restore original PDF")
    p_rev.add_argument("pdf", help="Path to the De-Identified PDF file")
    p_rev.add_argument("-k", "--key-vault", required=True, help="Path to the Re-ID Key Vault (.json)")
    p_rev.add_argument("-o", "--output", default=None, help="Output path for the restored PDF")
    p_rev.add_argument("--password", default=None, help="Vault password if encrypted")
    p_rev.set_defaults(func=cmd_reverse)

    # reidentify
    p_reid = sub.add_parser(
        "reidentify",
        help="Combine Key Vault + Cloud Analysis File (.csv, .json, .md, .txt, .pdf) to restore patient info",
    )
    p_reid.add_argument("input_file", help="Path to cloud analysis output file")
    p_reid.add_argument("-k", "--key-vault", required=True, help="Path to the Re-ID Key Vault (.json)")
    p_reid.add_argument("-o", "--output", default=None, help="Output path for the re-identified file")
    p_reid.add_argument("--password", default=None, help="Vault password if encrypted")
    p_reid.set_defaults(func=cmd_reidentify)

    # inspect
    p_insp = sub.add_parser("inspect", help="Inspect mappings stored inside a Re-ID Key Vault")
    p_insp.add_argument("key_vault", help="Path to the Re-ID Key Vault (.json)")
    p_insp.add_argument("--password", default=None, help="Vault password if encrypted")
    p_insp.set_defaults(func=cmd_inspect)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
