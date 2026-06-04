"""
NovaSentinel — Quarantine Manager
Professional-grade file isolation with AES-256 encryption and SQLite metadata.
"""

import os
import sqlite3
import shutil
import logging
import hashlib
from datetime import datetime
from typing import List, Dict, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)

class QuarantineManager:
    """
    Manages isolated files in an encrypted state.
    Each file is encrypted with AES-256 via Fernet (using a derived key).
    Metadata is stored in a dedicated SQLite database.
    """

    def __init__(self, base_path: str):
        self.base_path = base_path
        self.enc_dir = os.path.join(base_path, "vault")
        self.db_path = os.path.join(base_path, "quarantine.db")
        
        os.makedirs(self.enc_dir, exist_ok=True)
        self._init_db()
        self._key = self._derive_key("NovaSentinel-Vault-Secret-2024")

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                filename TEXT NOT NULL,
                vault_path TEXT NOT NULL,
                sha256 TEXT,
                reason TEXT,
                quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                size_bytes INTEGER
            )
        """)
        conn.commit()
        conn.close()

    def _derive_key(self, password: str) -> bytes:
        salt = b'NovaSentinel-Salt' # In production, this should be unique and stored
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def quarantine(self, file_path: str, reason: str = "Suspicious activity") -> bool:
        """Encrypt and move a file to the vault atomically."""
        if not os.path.exists(file_path):
            return False

        temp_vault = ""
        try:
            filename = os.path.basename(file_path)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            vault_name = f"{ts}_{filename}.nova"
            vault_path = os.path.join(self.enc_dir, vault_name)
            temp_vault = vault_path + ".tmp"
            
            # Read and encrypt
            with open(file_path, "rb") as f:
                data = f.read()
            
            fernet = Fernet(self._key)
            encrypted = fernet.encrypt(data)
            
            # Atomic write to vault
            with open(temp_vault, "wb") as f:
                f.write(encrypted)
            os.replace(temp_vault, vault_path)
            
            # Calculate SHA256 of original
            h = hashlib.sha256(data).hexdigest()
            size = len(data)
            
            # Store metadata in DB
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO quarantine (original_path, filename, vault_path, sha256, reason, size_bytes)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (file_path, filename, vault_path, h, reason, size))
            
            # Remove original only after successful encryption and DB commit
            os.remove(file_path)
            logger.info(f"Quarantined {file_path} to {vault_path}")
            return True
            
        except Exception as e:
            logger.error(f"Quarantine failed for {file_path}: {e}")
            if temp_vault and os.path.exists(temp_vault):
                try: os.remove(temp_vault)
                except: pass
            return False

    def restore(self, vault_path: str) -> bool:
        """Decrypt and restore a file to its original location atomically."""
        temp_restore = ""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT original_path FROM quarantine WHERE vault_path = ?", (vault_path,))
                row = cur.fetchone()
                
                if not row:
                    return False
                original_path = row[0]

            if not os.path.exists(vault_path):
                return False
                
            temp_restore = original_path + ".restoring"
            
            with open(vault_path, "rb") as f:
                encrypted_data = f.read()
            
            fernet = Fernet(self._key)
            decrypted = fernet.decrypt(encrypted_data)
            
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            with open(temp_restore, "wb") as f:
                f.write(decrypted)
            
            # Atomic move to original path
            os.replace(temp_restore, original_path)
                
            # Remove from vault and DB after successful restoration
            os.remove(vault_path)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM quarantine WHERE vault_path = ?", (vault_path,))
            
            logger.info(f"Restored {original_path} from {vault_path}")
            return True
        except Exception as e:
            logger.error(f"Restore failed for {vault_path}: {e}")
            if temp_restore and os.path.exists(temp_restore):
                try: os.remove(temp_restore)
                except: pass
            return False

    def delete(self, vault_path: str) -> bool:
        """Permanently delete a quarantined file."""
        try:
            if os.path.exists(vault_path):
                os.remove(vault_path)
            
            conn = sqlite3.connect(self.db_path)
            conn.execute("DELETE FROM quarantine WHERE vault_path = ?", (vault_path,))
            conn.commit()
            conn.close()
            logger.info(f"Permanently deleted quarantined file: {vault_path}")
            return True
        except Exception as e:
            logger.error(f"Delete failed for {vault_path}: {e}")
            return False

    def list_all(self) -> List[Dict]:
        """Return all quarantined items as a list of dicts."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM quarantine ORDER BY quarantined_at DESC")
        rows = cur.fetchall()
        items = [dict(r) for r in rows]
        conn.close()
        return items

_instance = None
def get_quarantine_manager() -> QuarantineManager:
    global _instance
    if _instance is None:
        base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "quarantine_vault")
        _instance = QuarantineManager(base)
    return _instance
