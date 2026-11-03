"""
Stage 2 Guard: Biomedical, Genomic, Oncology, and Literature Citation Whitelist.
Ensures zero false-positive redactions on clinical findings, gene symbols, variants,
therapies, trial IDs, or scientific references.
"""

import re
from typing import Set

# Null / placeholder clinical values that are never PHI
NON_PHI_PLACEHOLDERS: Set[str] = {
    "none",
    "not provided",
    "not applicable",
    "n/a",
    "na",
    "unknown",
    "not tested",
    "not detected",
    "detected",
    "cannot be determined",
    "blood",
    "tissue",
    "plasma",
    "serum",
    "saliva",
    "female",
    "male",
    "tw",
    "us",
    "foundation medicine laboratory",
    "foundation medicine, inc.",
    "foundation medicine",
    "foundationone liquid cdx",
    "foundationone cdx",
    "roche",
}

# Common oncology genes & biomarkers
GENE_AND_BIOMARKER_WHITELIST: Set[str] = {
    "ABL1", "ACVR1B", "AKT1", "AKT2", "AKT3", "ALK", "ALOX12B", "AMER1", "APC",
    "AR", "ARAF", "ARFRP1", "ARID1A", "ASXL1", "ATM", "ATR", "ATRX", "AURKA",
    "AURKB", "AXIN1", "AXL", "BAP1", "BARD1", "BCL2", "BCL2L1", "BCL2L2", "BCL6",
    "BCOR", "BCORL1", "BCR", "BRAF", "BRCA1", "BRCA2", "BRD4", "BRIP1", "BTG1",
    "BTG2", "BTK", "CALR", "CARD11", "CASP8", "CBFB", "CBL", "CCND1", "CCND2",
    "CCND3", "CCNE1", "CD22", "CD70", "CD74", "CD79A", "CD79B", "CD274", "CDC73",
    "CDH1", "CDK12", "CDK4", "CDK6", "CDK8", "CDKN1A", "CDKN1B", "CDKN2A", "CDKN2B",
    "CDKN2C", "CEBPA", "CHEK1", "CHEK2", "CIC", "CREBBP", "CRKL", "CSF1R", "CSF3R",
    "CTCF", "CTNNA1", "CTNNB1", "CUL3", "CUL4A", "CXCR4", "CYP17A1", "DAXX", "DDR1",
    "DDR2", "DIS3", "DNMT3A", "DOT1L", "EED", "EGFR", "EMSY", "EP300", "EPHA3",
    "EPHB1", "EPHB4", "ERBB2", "ERBB3", "ERBB4", "ERCC4", "ERG", "ERRFI1", "ESR1",
    "ETV4", "ETV5", "ETV6", "EWSR1", "EZH2", "EZR", "FANCA", "FANCC", "FANCG",
    "FANCL", "FAS", "FBXW7", "FGF10", "FGF12", "FGF14", "FGF19", "FGF23", "FGF3",
    "FGF4", "FGF6", "FGFR1", "FGFR2", "FGFR3", "FGFR4", "FH", "FLCN", "FLT1",
    "FLT3", "FOXL2", "FUBP1", "GABRA6", "GATA3", "GATA4", "GATA6", "GID4", "GNA11",
    "GNA13", "GNAQ", "GNAS", "GRM3", "GSK3B", "H3-3A", "HDAC1", "HGF", "HNF1A",
    "HRAS", "HSD3B1", "ID3", "IDH1", "IDH2", "IGF1R", "IKBKE", "IKZF1", "INPP4B",
    "IRF2", "IRF4", "IRS2", "JAK1", "JAK2", "JAK3", "JUN", "KDM5A", "KDM5C",
    "KDM6A", "KDR", "KEAP1", "KEL", "KIT", "KLHL6", "KMT2A", "KMT2D", "KRAS",
    "LTK", "LYN", "MAF", "MAP2K1", "MAP2K2", "MAP2K4", "MAP3K1", "MAP3K13", "MAPK1",
    "MCL1", "MDM2", "MDM4", "MED12", "MEF2B", "MEN1", "MERTK", "MET", "MITF",
    "MKNK1", "MLH1", "MPL", "MRE11", "MSH2", "MSH3", "MSH6", "MST1R", "MTAP",
    "MTOR", "MUTYH", "MYB", "MYC", "MYCL", "MYCN", "MYD88", "NBN", "NF1", "NF2",
    "NFE2L2", "NFKBIA", "NKX2-1", "NOTCH1", "NOTCH2", "NOTCH3", "NPM1", "NRAS",
    "NSD2", "NSD3", "NT5C2", "NTRK1", "NTRK2", "NTRK3", "NUTM1", "P2RY8", "PALB2",
    "PARP1", "PARP2", "PARP3", "PAX5", "PBRM1", "PDCD1", "PDCD1LG2", "PDGFRA",
    "PDGFRB", "PDK1", "PIK3C2B", "PIK3C2G", "PIK3CA", "PIK3CB", "PIK3R1", "PIM1",
    "PMS2", "POLD1", "POLE", "PPARG", "PPP2R1A", "PPP2R2A", "PRDM1", "PRKAR1A",
    "PRKCI", "PRKN", "PTCH1", "PTEN", "PTPN11", "PTPRO", "QKI", "RAC1", "RAD21",
    "RAD51", "RAD51B", "RAD51C", "RAD51D", "RAD52", "RAD54L", "RAF1", "RARA",
    "RB1", "RBM10", "REL", "RET", "RICTOR", "RNF43", "ROS1", "RPTOR", "RSPO2",
    "SDC4", "SDHA", "SDHB", "SDHC", "SDHD", "SETD2", "SF3B1", "SGK1", "SLC34A2",
    "SMAD2", "SMAD4", "SMARCA4", "SMARCB1", "SMO", "SNCAIP", "SOCS1", "SOX2",
    "SOX9", "SPEN", "SPOP", "SRC", "STAG2", "STAT3", "STK11", "SUFU", "SYK",
    "TBX3", "TEK", "TENT5C", "TERC", "TERT", "TET2", "TGFBR2", "TIPARP", "TMPRSS2",
    "TNFAIP3", "TNFRSF14", "TP53", "TSC1", "TSC2", "TYRO3", "U2AF1", "VEGFA",
    "VHL", "WT1", "XPO1", "XRCC2", "ZNF217", "ZNF703", "TMB", "BTMB", "MSI", "CTDNA",
}

# Regexes for genomic variants, clinical trial IDs, CLIA IDs, and scientific citations
BIOMEDICAL_PATTERNS = [
    re.compile(r"^NCT\d{8}$", re.IGNORECASE),
    re.compile(r"^NM_\d+(\.\d+)?", re.IGNORECASE),
    re.compile(r"^chr([0-9]{1,2}|X|Y|M|MT):\d+", re.IGNORECASE),
    re.compile(r"^[A-Z]\d+[A-Z\*]*(fs\*\d+|del|dup|ins)?$", re.IGNORECASE),
    re.compile(r"^c\.\d+[_\+\-\d]*[ACGTdelinsdup>]+", re.IGNORECASE),
    re.compile(r"^p\.[A-Z]\d+[A-Za-z0-9\*]+", re.IGNORECASE),
    re.compile(r"^\d+(\.\d+)?\s*(%|Muts/Mb)$", re.IGNORECASE),
    re.compile(r"^CLIA:\s*[0-9A-Z]+$", re.IGNORECASE),
    re.compile(r"^(22D2027531|34D2044309|D-ML-21105-01-00)$", re.IGNORECASE),
]

CITATION_LINE_PATTERNS = [
    re.compile(r"\bpmid:\s*\d+", re.IGNORECASE),
    re.compile(r"\bDOI:\s*10\.\d+", re.IGNORECASE),
    re.compile(r"\b(ASCO|AACR|ESMO|SABCS)\s+(GI\s+|GU\s+)?Abstract\b", re.IGNORECASE),
    re.compile(r"\bPubMed,\s*(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\b", re.IGNORECASE),
    re.compile(r"\bet\s+al\.,", re.IGNORECASE),
]


def is_whitelisted_value(value: str, line_context: str = "") -> bool:
    """
    Return True if `value` is a protected clinical/genomic term, placeholder, or citation
    that must NEVER be redacted.
    """
    cleaned = value.strip()
    if not cleaned:
        return True
    lower = cleaned.lower()
    if lower in NON_PHI_PLACEHOLDERS:
        return True
    if cleaned.upper() in GENE_AND_BIOMARKER_WHITELIST:
        return True
    for pat in BIOMEDICAL_PATTERNS:
        if pat.match(cleaned):
            return True
    if line_context:
        for cit_pat in CITATION_LINE_PATTERNS:
            if cit_pat.search(line_context):
                return True
    return False
