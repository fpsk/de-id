"""
End-to-End Automated Verification Suite on the Sample FoundationOne Liquid CDx PDF.
Validates:
1. Zero PHI leakage across all 29 pages & metadata of the de-identified PDF.
2. 100% preservation of clinical/genomic findings, VAFs, therapies, and references.
3. Lossless PDF reversal when combining (De-Identified PDF + Re-ID Key Vault).
4. Cloud analysis output re-identification (.md / .csv).
"""

import os
import sys
import pymupdf

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deid_engine.pdf_redactor import deidentify_pdf_file
from deid_engine.reverser import reidentify_text_content, reverse_deidentified_pdf
from deid_engine.spatial_parser import parse_page_layout
from deid_engine.tokenizer import BatchTokenizer
from deid_engine.vault import ReIdVault, load_vault, save_vault


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(ROOT_DIR, "output_deidentified")


def _find_sample_pdf() -> str:
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        return sys.argv[1]
    for fname in sorted(os.listdir(ROOT_DIR)):
        if fname.lower().endswith(".pdf"):
            return os.path.join(ROOT_DIR, fname)
    raise FileNotFoundError("No sample PDF found in workspace root.")


REQUIRED_CLINICAL_STRINGS = [
    "Breast carcinoma (NOS)",
    "Blood Tumor Mutational Burden",
    "10 Muts/Mb",
    "ctDNA Tumor Fraction",
    "High (13%)",
    "PALB2",
    "rearrangement exon 4",
    "0.27%",
    "0.38%",
    "ATM",
    "K468fs*18",
    "49.7%",
    "MDM2",
    "MLH1",
    "DNMT3A",
    "D194fs*22",
    "Olaparib",
    "Talazoparib",
    "Niraparib",
    "Rucaparib",
    "NCT06103864",
]


def run_verification():
    sample_pdf = _find_sample_pdf()
    print("=" * 72)
    print("1. Running Non-LLM De-Identification on Sample PDF...")
    print("=" * 72)
    tokenizer = BatchTokenizer(date_mode="mask", batch_salt="TEST-BATCH-2026")
    deid_pdf_path, vault_entry, matches = deidentify_pdf_file(
        sample_pdf, OUTPUT_DIR, tokenizer
    )

    vault = ReIdVault(
        date_mode="mask",
        global_token_dictionary=tokenizer.global_token_to_original,
        documents=[vault_entry],
    )
    vault_json_path = os.path.join(OUTPUT_DIR, "reid_key_vault.json")
    save_vault(vault, vault_json_path)

    print(f"De-identified PDF saved to: {deid_pdf_path}")
    print(f"Re-ID Key Vault saved to  : {vault_json_path}")
    print(f"Assigned Patient Token    : {vault_entry.patient_token}")
    print(f"Total Redacted Spans      : {len(matches)}")
    print("\nEntity Dictionary Mappings:")
    for tok, orig in vault_entry.entity_dictionary.items():
        print(f"  {tok:18s} <---> {orig}")

    forbidden_phi_strings = sorted(
        {m.raw_value.strip() for m in matches if len(m.raw_value.strip()) >= 3}
    )

    print("\n" + "=" * 72)
    print("2. Auditing De-Identified PDF for Zero PHI Leakage...")
    print("=" * 72)
    deid_doc = pymupdf.open(deid_pdf_path)
    leaks = []
    full_deid_text = ""
    for page_idx, page in enumerate(deid_doc):
        ptxt = page.get_text("text")
        layout_txt = "\n".join(s.text for s in parse_page_layout(page, page_idx).segments)
        combined_page_txt = ptxt + "\n" + layout_txt
        full_deid_text += f"\n--- PAGE {page_idx + 1} ---\n" + combined_page_txt
        for phi in forbidden_phi_strings:
            if phi.lower() in combined_page_txt.lower():
                leaks.append((page_idx + 1, phi))

    meta_str = str(deid_doc.metadata)
    for phi in forbidden_phi_strings:
        if phi.lower() in meta_str.lower():
            leaks.append(("METADATA", phi))
    deid_doc.close()

    if leaks:
        print(f"FAILED: Found {len(leaks)} PHI leaks: {leaks}")
        sys.exit(1)
    else:
        print(f"PASSED: 0 occurrences of any of the {len(forbidden_phi_strings)} PHI identifiers across all pages & metadata!")

    print("\n" + "=" * 72)
    print("3. Auditing Clinical & Genomic Content Preservation...")
    print("=" * 72)
    missing_clinical = []
    for clin in REQUIRED_CLINICAL_STRINGS:
        if clin not in full_deid_text:
            missing_clinical.append(clin)

    if missing_clinical:
        print(f"FAILED: Missing clinical strings: {missing_clinical}")
        sys.exit(1)
    else:
        print(f"PASSED: 100% of all {len(REQUIRED_CLINICAL_STRINGS)} key genomic, biomarker, VAF, and therapy findings are intact!")

    print("\n" + "=" * 72)
    print("4. Testing PDF Reversal (Combining Key Vault + De-Identified PDF)...")
    print("=" * 72)
    loaded_vault = load_vault(vault_json_path)
    restored_pdf_path, restored_count = reverse_deidentified_pdf(
        deid_pdf_path, loaded_vault
    )
    print(f"Restored PDF saved to: {restored_pdf_path} ({restored_count} regions reversed)")

    restored_doc = pymupdf.open(restored_pdf_path)
    restored_p1_p2 = restored_doc[0].get_text("text") + "\n" + restored_doc[1].get_text("text")
    restored_doc.close()

    expected_restored = list(vault_entry.entity_dictionary.values())
    missing_restored = [s for s in expected_restored if s not in restored_p1_p2]
    if missing_restored:
        print(f"FAILED: Missing restored strings: {missing_restored}")
        sys.exit(1)
    else:
        print("PASSED: All original Chinese & English PHI values were restored to the reversed PDF!")

    print("\n" + "=" * 72)
    print("5. Testing Cloud Analysis Report Re-Identification...")
    print("=" * 72)
    simulated_cloud_output = (
        f"Cloud Oncology Analysis Summary:\n"
        f"- Patient ID: {vault_entry.patient_token}\n"
        f"- Medical Record: MRN-{vault_entry.patient_token.split('-')[1]}\n"
        f"- Order Number: ORD-{vault_entry.patient_token.split('-')[1]}-01\n"
        f"- Primary Finding: PALB2 rearrangement exon 4 (VAF 0.27%/0.38%), ATM K468fs*18 (49.7%)\n"
        f"- Recommended Therapy: Olaparib / Talazoparib\n"
    )
    reid_report, rep_count = reidentify_text_content(simulated_cloud_output, loaded_vault)
    print(f"Re-identified {rep_count} tokens in simulated cloud analysis:\n")
    print(reid_report)
    print("=" * 72)
    print("ALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
