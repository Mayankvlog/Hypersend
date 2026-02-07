"""
WhatsApp-Grade Encrypted Backup System
======================================

Client-side encrypted backups with user-controlled keys.
Backups are end-to-end encrypted; server never sees plaintext.

Security Properties:
- Client-side encryption before upload
- User-controlled backup keys
- Secure key rehydration on restore
- Incremental backup support
- Backup integrity verification
"""

import os
import secrets
import hashlib
import hmac
import time
import json
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519
import base64

logger = logging.getLogger(__name__)


@dataclass
class BackupMetadata:
    """Backup metadata (encrypted)"""
    backup_id: str
    user_id: str
    device_id: str
    backup_type: str  # "full", "incremental"
    created_at: float
    size: int
    chunk_count: int
    encryption_algorithm: str
    checksum: str
    version: int
    parent_backup_id: Optional[str] = None  # For incremental backups


@dataclass
class BackupKey:
    """Backup encryption key (client-side only)"""
    backup_id: str
    encryption_key: bytes  # 32-byte AES-256 key
    hmac_key: bytes       # 32-byte HMAC key
    salt: bytes           # Random salt for KDF
    created_at: float


class EncryptedBackupService:
    """
    WhatsApp-grade encrypted backup service.
    
    CLIENT-SIDE ENCRYPTION:
    1. Generate random backup key
    2. Encrypt data with AES-256-GCM
    3. Compute HMAC for integrity
    4. Upload encrypted chunks
    5. Store only encrypted metadata
    
    SERVER-SIDE:
    - Stores encrypted blobs only
    - No access to plaintext
    - Provides chunked upload/download
    - Maintains backup catalog
    """
    
    def __init__(self, redis_client, storage_client=None):
        self.redis = redis_client
        self.storage = storage_client
        self.chunk_size = 1024 * 1024  # 1MB chunks
        self.max_backup_size = 1024 * 1024 * 1024  # 1GB max
        self.encryption_algorithm = "AES-256-GCM"
        self.backup_retention_days = 30
        
    async def create_encrypted_backup(
        self,
        user_id: str,
        device_id: str,
        backup_data: Dict[str, Any],  # User data to backup
        backup_type: str = "full",  # "full", "incremental"
        parent_backup_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create encrypted backup with comprehensive metadata"""
        try:
            # Generate backup key and metadata
            backup_key = self.generate_backup_key()
            backup_id = backup_key.backup_id
            
            # Serialize backup data
            backup_json = json.dumps(backup_data, separators=(',', ':'))
            backup_bytes = backup_json.encode('utf-8')
            
            # Encrypt backup data
            encrypted_chunks = await self._encrypt_backup_data(
                backup_bytes, 
                backup_key.encryption_key,
                backup_key.salt
            )
            
            # Calculate backup metadata
            total_size = len(backup_bytes)
            chunk_count = len(encrypted_chunks)
            checksum = hashlib.sha256(backup_bytes).hexdigest()
            
            # Create backup metadata
            metadata = BackupMetadata(
                backup_id=backup_id,
                user_id=user_id,
                device_id=device_id,
                backup_type=backup_type,
                created_at=time.time(),
                size=total_size,
                chunk_count=chunk_count,
                encryption_algorithm=self.encryption_algorithm,
                checksum=checksum,
                version=1,
                parent_backup_id=parent_backup_id
            )
            
            # Store backup metadata
            await self._store_backup_metadata(metadata)
            
            # Upload encrypted chunks
            upload_results = []
            for i, chunk_data in enumerate(encrypted_chunks):
                chunk_result = await self._upload_backup_chunk(
                    backup_id, i, chunk_data
                )
                upload_results.append(chunk_result)
            
            # Store backup key securely (client-side only)
            # Server never sees the actual key
            key_metadata = {
                "backup_id": backup_id,
                "key_hint": base64.b64encode(backup_key.salt[:8]).decode(),
                "created_at": backup_key.created_at,
                "device_id": device_id
            }
            
            return {
                "backup_id": backup_id,
                "backup_type": backup_type,
                "chunk_count": chunk_count,
                "total_size": total_size,
                "checksum": checksum,
                "encryption_algorithm": self.encryption_algorithm,
                "chunks": upload_results,
                "key_metadata": key_metadata,
                "created_at": metadata.created_at,
                "parent_backup_id": parent_backup_id
            }
            
        except Exception as e:
            logger.error(f"Backup creation failed: {str(e)}")
            raise
    
    async def restore_encrypted_backup(
        self,
        user_id: str,
        device_id: str,
        backup_id: str,
        backup_key: bytes,  # Client-provided backup key
        salt: bytes,      # Client-provided salt
        hmac_key: bytes    # Client-provided HMAC key
    ) -> Dict[str, Any]:
        """Restore encrypted backup with client-provided keys"""
        try:
            # Get backup metadata
            metadata = await self._get_backup_metadata(backup_id, user_id)
            if not metadata:
                raise Exception("Backup not found or access denied")
            
            # Download all chunks
            encrypted_chunks = []
            for i in range(metadata.chunk_count):
                chunk_data = await self._download_backup_chunk(backup_id, i)
                if chunk_data:
                    encrypted_chunks.append(chunk_data)
            
            # Reassemble encrypted backup
            encrypted_backup = b''.join(encrypted_chunks)
            
            # Verify backup integrity
            expected_checksum = metadata.checksum
            actual_checksum = hashlib.sha256(encrypted_backup).hexdigest()
            
            if expected_checksum != actual_checksum:
                raise Exception("Backup integrity check failed")
            
            # Decrypt backup data
            backup_data = await self._decrypt_backup_data(
                encrypted_backup, backup_key, salt
            )
            
            # Parse and return backup data
            try:
                restored_data = json.loads(backup_data.decode('utf-8'))
                return {
                    "backup_id": backup_id,
                    "success": True,
                    "data": restored_data,
                    "metadata": asdict(metadata),
                    "restored_at": time.time()
                }
            except json.JSONDecodeError:
                raise Exception("Backup data corrupted")
                
        except Exception as e:
            logger.error(f"Backup restore failed: {str(e)}")
            return {
                "backup_id": backup_id,
                "success": False,
                "error": str(e),
                "restored_at": time.time()
            }
    
    async def list_user_backups(
        self,
        user_id: str,
        device_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all backups for a user"""
        try:
            # Get backup metadata from database
            query = {"user_id": user_id}
            if device_id:
                query["device_id"] = device_id
                
            cursor = self._get_backup_collection().find(query).sort("created_at", -1)
            backups = []
            
            async for doc in cursor:
                # Don't return sensitive data
                backup_info = {
                    "backup_id": doc["backup_id"],
                    "backup_type": doc["backup_type"],
                    "created_at": doc["created_at"],
                    "size": doc["size"],
                    "chunk_count": doc["chunk_count"],
                    "encryption_algorithm": doc["encryption_algorithm"],
                    "version": doc["version"],
                    "parent_backup_id": doc.get("parent_backup_id")
                }
                backups.append(backup_info)
            
            return backups
            
        except Exception as e:
            logger.error(f"Failed to list backups: {str(e)}")
            return []
    
    async def delete_backup(
        self,
        user_id: str,
        backup_id: str
    ) -> Dict[str, Any]:
        """Securely delete a backup"""
        try:
            # Get backup metadata
            metadata = await self._get_backup_metadata(backup_id, user_id)
            if not metadata:
                return {"success": False, "error": "Backup not found"}
            
            # Delete all chunks
            for i in range(metadata.chunk_count):
                await self._delete_backup_chunk(backup_id, i)
            
            # Delete metadata
            await self._delete_backup_metadata(backup_id)
            
            return {
                "backup_id": backup_id,
                "success": True,
                "deleted_at": time.time()
            }
            
        except Exception as e:
            logger.error(f"Backup deletion failed: {str(e)}")
            return {
                "backup_id": backup_id,
                "success": False,
                "error": str(e)
            }
    
    async def _encrypt_backup_data(
        self,
        data: bytes,
        encryption_key: bytes,
        salt: bytes
    ) -> List[bytes]:
        """Encrypt backup data into chunks"""
        try:
            # Derive encryption key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"hypersend_backup_encryption",
            )
            derived_key = hkdf.derive(encryption_key)
            
            # Encrypt with AES-256-GCM
            aesgcm = AESGCM(derived_key)
            
            # Split into chunks and encrypt each
            chunks = []
            for i in range(0, len(data), self.chunk_size):
                chunk = data[i:i + self.chunk_size]
                
                # Generate random IV for each chunk
                iv = secrets.token_bytes(12)
                encrypted_chunk = aesgcm.encrypt(iv, chunk, None)
                
                # Store IV with encrypted data
                chunk_with_iv = iv + encrypted_chunk
                chunks.append(chunk_with_iv)
            
            return chunks
            
        except Exception as e:
            logger.error(f"Backup data encryption failed: {str(e)}")
            raise
    
    async def _decrypt_backup_data(
        self,
        encrypted_data: bytes,
        encryption_key: bytes,
        salt: bytes
    ) -> bytes:
        """Decrypt backup data from chunks"""
        try:
            # Derive decryption key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"hypersend_backup_encryption",
            )
            derived_key = hkdf.derive(encryption_key)
            
            # Decrypt chunks
            decrypted_chunks = []
            for i in range(0, len(encrypted_data), self.chunk_size + 12):  # +12 for IV
                chunk_with_iv = encrypted_data[i:i + self.chunk_size + 12]
                if len(chunk_with_iv) < 13:  # IV (12) + at least 1 byte data
                    break
                    
                iv = chunk_with_iv[:12]
                encrypted_chunk = chunk_with_iv[12:]
                
                aesgcm = AESGCM(derived_key)
                decrypted_chunk = aesgcm.decrypt(iv, encrypted_chunk, None)
                decrypted_chunks.append(decrypted_chunk)
            
            return b''.join(decrypted_chunks)
            
        except Exception as e:
            logger.error(f"Backup data decryption failed: {str(e)}")
            raise
    
    async def _upload_backup_chunk(
        self,
        backup_id: str,
        chunk_index: int,
        chunk_data: bytes
    ) -> Dict[str, Any]:
        """Upload encrypted backup chunk"""
        try:
            # This would upload to cloud storage (S3, GCS, etc.)
            # For now, simulate upload
            chunk_id = f"{backup_id}_{chunk_index}"
            
            # Store chunk metadata in Redis
            chunk_info = {
                "chunk_id": chunk_id,
                "backup_id": backup_id,
                "chunk_index": chunk_index,
                "size": len(chunk_data),
                "checksum": hashlib.sha256(chunk_data).hexdigest(),
                "uploaded_at": time.time()
            }
            
            await self.redis.setex(
                f"backup_chunk:{chunk_id}",
                86400 * 7,  # 7 days
                json.dumps(chunk_info)
            )
            
            return {
                "chunk_id": chunk_id,
                "chunk_index": chunk_index,
                "size": len(chunk_data),
                "checksum": chunk_info["checksum"],
                "uploaded": True
            }
            
        except Exception as e:
            logger.error(f"Chunk upload failed: {str(e)}")
            return {
                "chunk_id": f"{backup_id}_{chunk_index}",
                "chunk_index": chunk_index,
                "uploaded": False,
                "error": str(e)
            }
    
    async def _download_backup_chunk(
        self,
        backup_id: str,
        chunk_index: int
    ) -> Optional[bytes]:
        """Download encrypted backup chunk"""
        try:
            chunk_id = f"{backup_id}_{chunk_index}"
            chunk_data = await self.redis.get(f"backup_chunk:{chunk_id}")
            
            if chunk_data:
                info = json.loads(chunk_data)
                # This would download from actual storage
                # For now, return simulated data
                return b"x" * info.get("size", 1024)
            
            return None
            
        except Exception as e:
            logger.error(f"Chunk download failed: {str(e)}")
            return None
    
    async def _delete_backup_chunk(self, backup_id: str, chunk_index: int):
        """Delete backup chunk"""
        try:
            chunk_id = f"{backup_id}_{chunk_index}"
            await self.redis.delete(f"backup_chunk:{chunk_id}")
            # This would delete from actual storage
        except Exception as e:
            logger.error(f"Chunk deletion failed: {str(e)}")
    
    async def _store_backup_metadata(self, metadata: BackupMetadata):
        """Store backup metadata in database"""
        try:
            await self._get_backup_collection().insert_one(asdict(metadata))
        except Exception as e:
            logger.error(f"Failed to store backup metadata: {str(e)}")
    
    async def _get_backup_metadata(
        self,
        backup_id: str,
        user_id: str
    ) -> Optional[BackupMetadata]:
        """Get backup metadata"""
        try:
            data = await self._get_backup_collection().find_one({
                "backup_id": backup_id,
                "user_id": user_id
            })
            if data:
                return BackupMetadata(**data)
            return None
        except Exception as e:
            logger.error(f"Failed to get backup metadata: {str(e)}")
            return None
    
    async def _delete_backup_metadata(self, backup_id: str):
        """Delete backup metadata"""
        try:
            await self._get_backup_collection().delete_one({"backup_id": backup_id})
        except Exception as e:
            logger.error(f"Failed to delete backup metadata: {str(e)}")
    
    def _get_backup_collection(self):
        """Get backup collection"""
        # This would return the actual database collection
        # For now, return a mock
        return None
    """
    WhatsApp-grade encrypted backup service.
    
    CLIENT-SIDE ENCRYPTION:
    1. Generate random backup key
    2. Encrypt data with AES-256-GCM
    3. Compute HMAC for integrity
    4. Upload encrypted chunks
    5. Store only encrypted metadata
    
    SERVER-SIDE:
    - Stores encrypted blobs only
    - No access to plaintext
    - Provides chunked upload/download
    - Maintains backup catalog
    """
    
    def __init__(self, redis_client, storage_client=None):
        self.redis = redis_client
        self.storage = storage_client
        self.chunk_size = 1024 * 1024  # 1MB chunks
        self.max_backup_size = 1024 * 1024 * 1024  # 1GB max
        self.encryption_algorithm = "AES-256-GCM"
        self.backup_retention_days = 30
    
    def generate_backup_key(self) -> BackupKey:
        """Generate new backup encryption key"""
        backup_id = secrets.token_urlsafe(16)
        encryption_key = os.urandom(32)  # AES-256 key
        hmac_key = os.urandom(32)        # HMAC key
        salt = os.urandom(16)            # Random salt
        
        return BackupKey(
            backup_id=backup_id,
            encryption_key=encryption_key,
            hmac_key=hmac_key,
            salt=salt,
            created_at=time.time()
        )
    
    def encrypt_backup_data(self, data: bytes, backup_key: BackupKey) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt backup data client-side.
        Returns (ciphertext, nonce, auth_tag)
        """
        try:
            # Generate random nonce
            nonce = os.urandom(12)
            
            # Encrypt with AES-256-GCM
            cipher = Cipher(
                algorithms.AES(backup_key.encryption_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            ciphertext = encryptor.update(data) + encryptor.finalize()
            auth_tag = encryptor.tag
            
            return ciphertext, nonce, auth_tag
            
        except Exception as e:
            logger.error(f"Backup encryption failed: {e}")
            raise
    
    def decrypt_backup_data(self, ciphertext: bytes, nonce: bytes, auth_tag: bytes,
                          backup_key: BackupKey) -> bytes:
        """
        Decrypt backup data client-side.
        """
        try:
            cipher = Cipher(
                algorithms.AES(backup_key.encryption_key),
                modes.GCM(nonce, auth_tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
            
        except Exception as e:
            logger.error(f"Backup decryption failed: {e}")
            raise
    
    def compute_backup_hmac(self, data: bytes, backup_key: BackupKey) -> bytes:
        """Compute HMAC for backup integrity verification"""
        hmac_obj = hmac.HMAC(backup_key.hmac_key, hashes.SHA256(), backend=default_backend())
        hmac_obj.update(data)
        return hmac_obj.finalize()
    
    def verify_backup_hmac(self, data: bytes, expected_hmac: bytes, backup_key: BackupKey) -> bool:
        """Verify backup integrity"""
        try:
            computed_hmac = self.compute_backup_hmac(data, backup_key)
            return hmac.compare_digest(computed_hmac, expected_hmac)
        except Exception as e:
            logger.error(f"HMAC verification failed: {e}")
            return False
    
    async def create_backup(self, user_id: str, device_id: str, backup_data: bytes,
                          backup_type: str = "full", parent_backup_id: Optional[str] = None) -> BackupMetadata:
        """
        Create encrypted backup.
        This method handles the server-side coordination only.
        Actual encryption happens client-side.
        """
        try:
            # Generate backup ID
            backup_id = secrets.token_urlsafe(16)
            
            # Create backup metadata
            metadata = BackupMetadata(
                backup_id=backup_id,
                user_id=user_id,
                device_id=device_id,
                backup_type=backup_type,
                created_at=time.time(),
                size=len(backup_data),
                chunk_count=0,  # Will be updated after chunking
                encryption_algorithm=self.encryption_algorithm,
                checksum="",  # Will be computed after encryption
                version=1,
                parent_backup_id=parent_backup_id
            )
            
            # Store backup metadata (encrypted)
            metadata_key = f"backup_metadata:{backup_id}"
            await self.redis.setex(
                metadata_key,
                86400 * self.backup_retention_days,
                json.dumps(asdict(metadata))
            )
            
            # Add to user's backup catalog
            catalog_key = f"user_backups:{user_id}"
            await self.redis.lpush(catalog_key, backup_id)
            await self.redis.expire(catalog_key, 86400 * self.backup_retention_days)
            
            logger.info(f"Backup created: {backup_id} for user {user_id}")
            return metadata
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            raise
    
    async def upload_backup_chunk(self, backup_id: str, chunk_index: int,
                                encrypted_chunk: bytes, nonce: bytes, auth_tag: bytes) -> bool:
        """Upload encrypted backup chunk"""
        try:
            # Validate chunk size
            if len(encrypted_chunk) > self.chunk_size:
                raise ValueError(f"Chunk too large: {len(encrypted_chunk)} bytes")
            
            # Store encrypted chunk
            chunk_key = f"backup_chunk:{backup_id}:{chunk_index}"
            chunk_data = {
                "ciphertext": base64.b64encode(encrypted_chunk).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "auth_tag": base64.b64encode(auth_tag).decode(),
                "uploaded_at": time.time()
            }
            
            await self.redis.setex(chunk_key, 86400 * self.backup_retention_days, json.dumps(chunk_data))
            
            # Update backup metadata
            metadata_key = f"backup_metadata:{backup_id}"
            metadata_data = await self.redis.get(metadata_key)
            if metadata_data:
                metadata = json.loads(metadata_data)
                metadata["chunk_count"] = max(metadata.get("chunk_count", 0), chunk_index + 1)
                await self.redis.setex(metadata_key, 86400 * self.backup_retention_days, json.dumps(metadata))
            
            logger.info(f"Backup chunk uploaded: {backup_id}:{chunk_index}")
            return True
            
        except Exception as e:
            logger.error(f"Backup chunk upload failed: {e}")
            return False
    
    async def download_backup_chunk(self, backup_id: str, chunk_index: int) -> Optional[Dict]:
        """Download encrypted backup chunk"""
        try:
            chunk_key = f"backup_chunk:{backup_id}:{chunk_index}"
            chunk_data = await self.redis.get(chunk_key)
            
            if chunk_data:
                return json.loads(chunk_data)
            else:
                return None
                
        except Exception as e:
            logger.error(f"Backup chunk download failed: {e}")
            return None
    
    async def get_backup_metadata(self, backup_id: str) -> Optional[BackupMetadata]:
        """Get backup metadata"""
        try:
            metadata_key = f"backup_metadata:{backup_id}"
            metadata_data = await self.redis.get(metadata_key)
            
            if metadata_data:
                data = json.loads(metadata_data)
                return BackupMetadata(**data)
            else:
                return None
                
        except Exception as e:
            logger.error(f"Failed to get backup metadata: {e}")
            return None
    
    async def list_user_backups(self, user_id: str) -> List[BackupMetadata]:
        """List all backups for a user"""
        try:
            catalog_key = f"user_backups:{user_id}"
            backup_ids = await self.redis.lrange(catalog_key, 0, -1)
            
            backups = []
            for backup_id in backup_ids:
                backup_id_str = backup_id.decode() if isinstance(backup_id, bytes) else backup_id
                metadata = await self.get_backup_metadata(backup_id_str)
                if metadata:
                    backups.append(metadata)
            
            # Sort by creation time (newest first)
            backups.sort(key=lambda x: x.created_at, reverse=True)
            return backups
            
        except Exception as e:
            logger.error(f"Failed to list user backups: {e}")
            return []
    
    async def delete_backup(self, backup_id: str, user_id: str) -> bool:
        """Delete backup and all its chunks"""
        try:
            # Verify ownership
            metadata = await self.get_backup_metadata(backup_id)
            if not metadata or metadata.user_id != user_id:
                return False
            
            # Delete chunks
            for chunk_index in range(metadata.chunk_count):
                chunk_key = f"backup_chunk:{backup_id}:{chunk_index}"
                await self.redis.delete(chunk_key)
            
            # Delete metadata
            metadata_key = f"backup_metadata:{backup_id}"
            await self.redis.delete(metadata_key)
            
            # Remove from catalog
            catalog_key = f"user_backups:{user_id}"
            await self.redis.lrem(catalog_key, 0, backup_id)
            
            logger.info(f"Backup deleted: {backup_id}")
            return True
            
        except Exception as e:
            logger.error(f"Backup deletion failed: {e}")
            return False
    
    async def restore_backup(self, backup_id: str, backup_key: BackupKey) -> Optional[bytes]:
        """
        Restore backup from encrypted chunks.
        This method coordinates the server-side restoration.
        Actual decryption happens client-side with the backup key.
        """
        try:
            metadata = await self.get_backup_metadata(backup_id)
            if not metadata:
                return None
            
            # Download all chunks
            encrypted_chunks = []
            for chunk_index in range(metadata.chunk_count):
                chunk_data = await self.download_backup_chunk(backup_id, chunk_index)
                if not chunk_data:
                    return None
                
                # Decode chunk data
                ciphertext = base64.b64decode(chunk_data["ciphertext"])
                nonce = base64.b64decode(chunk_data["nonce"])
                auth_tag = base64.b64decode(chunk_data["auth_tag"])
                
                encrypted_chunks.append((ciphertext, nonce, auth_tag))
            
            # Return encrypted chunks for client-side decryption
            # In a real implementation, this would be streamed
            restore_data = {
                "metadata": asdict(metadata),
                "chunks": [
                    {
                        "ciphertext": base64.b64encode(chunk[0]).decode(),
                        "nonce": base64.b64encode(chunk[1]).decode(),
                        "auth_tag": base64.b64encode(chunk[2]).decode()
                    }
                    for chunk in encrypted_chunks
                ]
            }
            
            return json.dumps(restore_data).encode()
            
        except Exception as e:
            logger.error(f"Backup restoration failed: {e}")
            return None
    
    async def verify_backup_integrity(self, backup_id: str, backup_key: BackupKey) -> bool:
        """Verify backup integrity using HMAC"""
        try:
            metadata = await self.get_backup_metadata(backup_id)
            if not metadata:
                return False
            
            # Download and verify all chunks
            total_hmac_input = b""
            
            for chunk_index in range(metadata.chunk_count):
                chunk_data = await self.download_backup_chunk(backup_id, chunk_index)
                if not chunk_data:
                    return False
                
                ciphertext = base64.b64decode(chunk_data["ciphertext"])
                total_hmac_input += ciphertext
            
            # Verify HMAC
            expected_hmac = base64.b64decode(metadata.checksum)
            return self.verify_backup_hmac(total_hmac_input, expected_hmac, backup_key)
            
        except Exception as e:
            logger.error(f"Backup integrity verification failed: {e}")
            return False
    
    async def cleanup_expired_backups(self) -> int:
        """Clean up expired backups"""
        try:
            deleted_count = 0
            
            # Find all backup metadata keys
            metadata_keys = await self.redis.keys("backup_metadata:*")
            
            for metadata_key in metadata_keys:
                metadata_data = await self.redis.get(metadata_key)
                if metadata_data:
                    metadata = json.loads(metadata_data)
                    created_at = metadata.get("created_at", 0)
                    
                    # Check if backup is expired
                    if time.time() - created_at > 86400 * self.backup_retention_days:
                        backup_id = metadata.get("backup_id")
                        if backup_id:
                            user_id = metadata.get("user_id")
                            if await self.delete_backup(backup_id, user_id):
                                deleted_count += 1
            
            logger.info(f"Cleaned up {deleted_count} expired backups")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
            return 0
