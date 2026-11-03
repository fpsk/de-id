"""
Stage 3: Patient-Consistent Batch Tokenizer.
Links multiple PDFs belonging to the same patient across a batch and assigns
HIPAA Safe Harbor compliant pseudonym tokens (with support for Date Masking or Date Shifting).
"""

from datetime import date, timedelta
import hashlib
import secrets
from typing import Dict, List, Optional, Tuple

from .phi_detector import PHIMatch


class BatchTokenizer:
    """
    Maintains consistent patient and entity pseudonym mappings across a batch of PDF documents.
    """

    def __init__(self, date_mode: str = "mask", batch_salt: Optional[str] = None):
        """
        :param date_mode: 'mask' (HIPAA Safe Harbor year-only / chronological date tokens)
                          or 'shift' (consistent random day offset per patient).
        :param batch_salt: Optional secret salt for deterministic token generation within a batch.
        """
        self.date_mode = date_mode
        self.batch_salt = batch_salt or secrets.token_hex(8)
        # Canonical patient identity -> patient_code (e.g. '8F3A2C')
        self.patient_codes: Dict[str, str] = {}
        # Per-patient canonical_key -> assigned pseudonym token
        self.patient_entity_tokens: Dict[str, Dict[str, str]] = {}
        # Global reverse dictionary: token -> human-readable original summary
        self.global_token_to_original: Dict[str, str] = {}

    def _derive_code(self, key: str, length: int = 6) -> str:
        digest = hashlib.sha256(f"{self.batch_salt}:{key}".encode("utf-8")).hexdigest().upper()
        return digest[:length]

    def resolve_patient_code(self, matches: List[PHIMatch], fallback_name: str) -> str:
        """
        Identify the canonical patient across a document using MRN or PATIENT_NAME + DOB.
        """
        mrn_keys = [m.canonical_key for m in matches if m.category == "MRN"]
        name_keys = [m.canonical_key for m in matches if m.category == "PATIENT_NAME"]
        dob_keys = [m.canonical_key for m in matches if m.category == "DOB"]

        if mrn_keys:
            ident = mrn_keys[0]
        elif name_keys and dob_keys:
            ident = f"{name_keys[0]}|{dob_keys[0]}"
        elif name_keys:
            ident = name_keys[0]
        else:
            ident = f"DOC:{fallback_name}"

        if ident not in self.patient_codes:
            code = self._derive_code(ident, length=6)
            self.patient_codes[ident] = code
            self.patient_entity_tokens[code] = {}
        return self.patient_codes[ident]

    def _shift_iso_date(self, iso_str: str, pat_code: str) -> str:
        try:
            parts = [int(p) for p in iso_str.split("-")]
            dt = date(parts[0], parts[1], parts[2])
            # Deterministic offset between -180 and -31 days for this patient
            offset_val = int(hashlib.sha256(f"SHIFT:{self.batch_salt}:{pat_code}".encode()).hexdigest()[:4], 16)
            days_shift = -(31 + (offset_val % 150))
            shifted = dt + timedelta(days=days_shift)
            return shifted.isoformat()
        except Exception:
            return f"{iso_str[:4]}-XX-XX"

    def assign_tokens(
        self, matches: List[PHIMatch], source_filename: str
    ) -> Tuple[str, str, Dict[str, str]]:
        """
        Assign tokens to all `PHIMatch` items in a document.
        Returns `(patient_token, deidentified_filename, document_entity_dictionary)`.
        """
        pat_code = self.resolve_patient_code(matches, source_filename)
        patient_token = f"PAT-{pat_code}"
        ent_map = self.patient_entity_tokens[pat_code]

        # Pre-sort all distinct clinical dates chronologically so DATE-01, DATE-02 are ordered
        date_canon_keys = sorted(
            {
                m.canonical_key
                for m in matches
                if m.canonical_key.startswith("DATE:")
            }
        )
        for idx, d_key in enumerate(date_canon_keys, start=1):
            if d_key not in ent_map:
                iso_part = d_key.split(":", 1)[1]
                year_str = iso_part[:4]
                if self.date_mode == "shift":
                    ent_map[d_key] = self._shift_iso_date(iso_part, pat_code)
                else:
                    ent_map[d_key] = f"{year_str}-DATE-{idx:02d}"

        # Track counters for multi-valued categories per patient
        cat_counters: Dict[str, int] = {}

        # Group original surface forms per canonical_key to build a rich summary string
        canon_originals: Dict[str, List[str]] = {}
        for m in matches:
            canon_originals.setdefault(m.canonical_key, [])
            if m.raw_value not in canon_originals[m.canonical_key]:
                canon_originals[m.canonical_key].append(m.raw_value)

        for m in matches:
            ckey = m.canonical_key
            if ckey not in ent_map:
                if m.category == "PATIENT_NAME":
                    ent_map[ckey] = patient_token
                elif m.category == "DOB":
                    iso_part = ckey.split(":", 1)[1] if ":" in ckey else "1900-01-01"
                    try:
                        birth_year = int(iso_part[:4])
                        current_year = date.today().year
                        # HIPAA Safe Harbor: ages > 89 must be aggregated
                        if current_year - birth_year > 89:
                            ent_map[ckey] = "1900-XX-XX"
                        elif self.date_mode == "shift":
                            ent_map[ckey] = self._shift_iso_date(iso_part, pat_code)
                        else:
                            ent_map[ckey] = f"{birth_year:04d}-XX-XX"
                    except Exception:
                        ent_map[ckey] = "XXXX-XX-XX"
                elif m.category == "MRN":
                    ent_map[ckey] = f"MRN-{pat_code}"
                elif m.category == "ORDER_ID":
                    cat_counters["ORDER_ID"] = cat_counters.get("ORDER_ID", 0) + 1
                    ent_map[ckey] = f"ORD-{pat_code}-{cat_counters['ORDER_ID']:02d}"
                elif m.category == "SPECIMEN_ID":
                    cat_counters["SPECIMEN_ID"] = cat_counters.get("SPECIMEN_ID", 0) + 1
                    ent_map[ckey] = f"SPEC-{pat_code}-{cat_counters['SPECIMEN_ID']:02d}"
                elif m.category == "PHYSICIAN":
                    cat_counters["PHYSICIAN"] = cat_counters.get("PHYSICIAN", 0) + 1
                    ent_map[ckey] = f"PHYS-{pat_code}-{cat_counters['PHYSICIAN']:02d}"
                elif m.category == "FACILITY":
                    ent_map[ckey] = f"FACILITY-{pat_code}"
                elif m.category == "FACILITY_ID":
                    ent_map[ckey] = f"FACID-{pat_code}"
                else:
                    cat_counters["OTHER"] = cat_counters.get("OTHER", 0) + 1
                    ent_map[ckey] = f"ID-{pat_code}-{cat_counters['OTHER']:02d}"

            m.token = ent_map[ckey]

        # Build human-readable dictionary: token -> combined original surface strings
        doc_entity_dict: Dict[str, str] = {}
        for ckey, orig_list in canon_originals.items():
            tok = ent_map[ckey]
            combined = " / ".join(orig_list)
            doc_entity_dict[tok] = combined
            self.global_token_to_original[tok] = combined

        # Build sanitized filename
        ord_tokens = [tok for ckey, tok in ent_map.items() if ckey.startswith("ORDER_ID:")]
        ord_suffix = f"_{ord_tokens[0]}" if ord_tokens else ""
        deid_filename = f"DEID_{patient_token}{ord_suffix}.pdf"

        return patient_token, deid_filename, doc_entity_dict
