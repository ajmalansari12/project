"""SHA-256 file hashing and digest verification service for Sentinel-EDR.

Implements memory-bounded chunked hashing for files and byte streams, deterministic
lowercase hexadecimal normalization, and strict validation.
"""

import hashlib
import os
from pathlib import Path
import re
from typing import Union

from app.services.errors import ValidationError

DEFAULT_CHUNK_SIZE: int = 65536  # 64 KB
HEX_64_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def is_valid_sha256(digest: str) -> bool:
    """Check if the provided string is a valid 64-character hexadecimal SHA-256 digest."""
    if not isinstance(digest, str):
        return False
    return bool(HEX_64_PATTERN.match(digest.strip()))


def normalize_sha256(digest: str) -> str:
    """Normalize and validate a SHA-256 digest string to lowercase hexadecimal.

    Raises:
        ValidationError: If the digest is None, empty, or not a valid 64-character hex string.
    """
    if not digest or not isinstance(digest, str):
        raise ValidationError(
            "file_hash is required and must be a 64-character hexadecimal string.",
            field="file_hash",
        )
    normalized = digest.strip().lower()
    if not HEX_64_PATTERN.match(normalized):
        raise ValidationError(
            f"Invalid SHA-256 hash digest '{digest}': must be exactly 64 hexadecimal characters.",
            field="file_hash",
        )
    return normalized


def compute_file_sha256(
    file_path: Union[str, Path],
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """Compute the SHA-256 hash digest of a file using fixed-size incremental chunks.

    Reads files sequentially in fixed-size buffers to avoid loading large files
    into memory. Returns a deterministic 64-character lowercase hexadecimal digest.

    Args:
        file_path: Filesystem path to the target file.
        chunk_size: Number of bytes to read per buffer iteration. Must be > 0.

    Returns:
        Lowercase 64-character hexadecimal SHA-256 digest.

    Raises:
        ValueError: If chunk_size <= 0 or path is not a regular file.
        FileNotFoundError: If the target file path does not exist.
        IsADirectoryError: If the target path points to a directory.
        PermissionError: If the process does not have permission to read the file.
        OSError: If an operating-system level I/O error occurs during reading.
    """
    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be a positive integer, got: {chunk_size}")

    path_obj = Path(file_path).resolve()

    if not path_obj.exists():
        raise FileNotFoundError(f"Target file does not exist: {file_path}")

    if path_obj.is_dir():
        raise IsADirectoryError(f"Target path is a directory, not a regular file: {file_path}")

    if not path_obj.is_file():
        raise ValueError(f"Target path is not a regular file: {file_path}")

    hasher = hashlib.sha256()

    with open(path_obj, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest().lower()


def compute_bytes_sha256(data: bytes) -> str:
    """Compute the SHA-256 hash digest of a byte sequence in memory.

    Args:
        data: Raw byte sequence to hash.

    Returns:
        Lowercase 64-character hexadecimal SHA-256 digest.

    Raises:
        TypeError: If data is not bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Expected bytes or bytearray, got {type(data).__name__}")
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest().lower()
