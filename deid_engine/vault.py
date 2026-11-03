"""
Stage 4: Re-Identification Key Vault Serialization & Optional AES Encryption.
Stores both high-level entity dictionaries (for cloud report re-identification)
and coordinate/style restoration records (for reversing a de-identified PDF back to the original PDF).
"""

import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class CoordinateRestorationRecord:
    page_num: int
    original_bbox: List[float]
    token_bbox: List[float]
    origin: List[float]
    fontsize: float
    color_int: int
    token_text: str
    category: str
    raw_value: str
    original_spans: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class DocumentVaultEntry:
    patient_token: str
    original_filename: str
    deidentified_filename: str
    original_sha256: str
    deidentified_sha256: str
    original_metadata: Dict[str, Any]
    entity_dictionary: Dict[str, str]
    coordinate_records: List[CoordinateRestorationRecord] = field(default_factory=list)


@dataclass
class ReIdVault:
    schema_version: str = "2.0"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    date_mode: str = "mask"
    global_token_dictionary: Dict[str, str] = field(default_factory=dict)
    documents: List[DocumentVaultEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReIdVault":
        docs: List[DocumentVaultEntry] = []
        for d in data.get("documents", []):
            coords = [
                CoordinateRestorationRecord(**c)
                for c in d.get("coordinate_records", [])
            ]
            docs.append(
                DocumentVaultEntry(
                    patient_token=d["patient_token"],
                    original_filename=d["original_filename"],
                    deidentified_filename=d["deidentified_filename"],
                    original_sha256=d.get("original_sha256", ""),
                    deidentified_sha256=d.get("deidentified_sha256", ""),
                    original_metadata=d.get("original_metadata", {}),
                    entity_dictionary=d.get("entity_dictionary", {}),
                    coordinate_records=coords,
                )
            )
        return cls(
            schema_version=data.get("schema_version", "2.0"),
            created_at=data.get("created_at", ""),
            date_mode=data.get("date_mode", "mask"),
            global_token_dictionary=data.get("global_token_dictionary", {}),
            documents=docs,
        )


def _derive_fernet_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def save_vault(vault: ReIdVault, output_path: str, password: Optional[str] = None) -> str:
    """
    Save the ReIdVault to disk as JSON or password-encrypted JSON wrapper.
    """
    payload_bytes = json.dumps(vault.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")
    if password:
        salt = os.urandom(16)
        key = _derive_fernet_key(password, salt)
        token = Fernet(key).encrypt(payload_bytes)
        wrapper = {
            "encrypted": True,
            "kdf": "PBKDF2-SHA256-200000",
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "ciphertext_b64": base64.b64encode(token).decode("ascii"),
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(wrapper, f, indent=2)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(payload_bytes.decode("utf-8"))
    return output_path


def load_vault(vault_path: str, password: Optional[str] = None) -> ReIdVault:
    """
    Load a ReIdVault from disk, decrypting if password-protected.
    """
    with open(vault_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if isinstance(raw, dict) and raw.get("encrypted") is True:
        if not password:
            raise ValueError("This Re-ID Key Vault is encrypted. Please provide the vault password.")
        salt = base64.b64decode(raw["salt_b64"])
        ciphertext = base64.b64decode(raw["ciphertext_b64"])
        key = _derive_fernet_key(password, salt)
        try:
            decrypted = Fernet(key).decrypt(ciphertext)
        except Exception as exc:
            raise ValueError("Invalid password for encrypted Re-ID Key Vault.") from exc
        data = json.loads(decrypted.decode("utf-8"))
        return ReIdVault.from_dict(data)

    return ReIdVault.from_dict(raw)
