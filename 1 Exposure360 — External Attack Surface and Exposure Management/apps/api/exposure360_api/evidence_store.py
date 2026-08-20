import hashlib
import io
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from functools import lru_cache
from typing import Any, BinaryIO, Protocol, cast
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]

from .config import Settings, get_settings
from .models import Evidence

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_SAFE_CONTENT_TYPES = {
    "application/json",
    "application/octet-stream",
    "application/pem-certificate-chain",
    "text/plain",
}


class EvidenceStoreError(ValueError):
    """Raised when evidence object storage or access policy validation fails."""


class EvidenceIntegrityStatus(StrEnum):
    PASS = "PASS"
    HASH_MISMATCH = "HASH_MISMATCH"
    OBJECT_MISSING = "OBJECT_MISSING"


@dataclass(frozen=True)
class StoredEvidenceObject:
    bucket: str
    key: str
    sha256: str
    size_bytes: int
    media_type: str


@dataclass(frozen=True)
class EvidenceObjectHead:
    size_bytes: int
    media_type: str


@dataclass(frozen=True)
class DownloadReference:
    url: str
    expires_at: datetime
    content_disposition: str


@dataclass(frozen=True)
class IntegrityVerification:
    status: EvidenceIntegrityStatus
    expected_sha256: str
    actual_sha256: str | None
    size_bytes: int | None


class ReadableObject(Protocol):
    def read(self, amount: int = -1) -> bytes: ...

    def close(self) -> None: ...


class WritableObject(Protocol):
    def write(self, data: bytes) -> int: ...


class EvidenceObjectStore(Protocol):
    """Private object-store contract used by evidence services and retrieval routes."""

    def put_stream(
        self,
        *,
        organization_id: UUID,
        evidence_id: UUID,
        collected_at: datetime,
        stream: BinaryIO,
        media_type: str | None,
    ) -> StoredEvidenceObject: ...

    def head(self, *, bucket: str, key: str) -> EvidenceObjectHead | None: ...

    def open_stream(self, *, bucket: str, key: str) -> ReadableObject | None: ...

    def create_download_reference(
        self,
        *,
        bucket: str,
        key: str,
        filename: str,
        ttl_seconds: int,
    ) -> DownloadReference: ...


class Boto3EvidenceObjectStore:
    """S3-compatible private storage adapter for MinIO or managed object storage."""

    def __init__(self, settings: Settings) -> None:
        self._bucket = settings.objectstore_bucket
        self._max_object_bytes = settings.evidence_max_object_bytes
        self._signed_url_ttl_seconds = settings.evidence_signed_url_ttl_seconds
        self._server_side_encryption = settings.objectstore_server_side_encryption
        self._client: Any = boto3.client(
            "s3",
            endpoint_url=str(settings.objectstore_endpoint),
            aws_access_key_id=settings.objectstore_access_key,
            aws_secret_access_key=settings.objectstore_secret_key,
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )

    def put_stream(
        self,
        *,
        organization_id: UUID,
        evidence_id: UUID,
        collected_at: datetime,
        stream: BinaryIO,
        media_type: str | None,
    ) -> StoredEvidenceObject:
        resolved_media_type = safe_media_type(media_type)
        with tempfile.SpooledTemporaryFile(max_size=1_048_576, mode="w+b") as spool:
            digest, size_bytes = self._copy_and_hash(stream, spool)
            key = evidence_object_key(organization_id, evidence_id, collected_at, digest)
            spool.seek(0)
            upload_args: dict[str, Any] = {"ContentType": resolved_media_type}
            if self._server_side_encryption:
                upload_args["ServerSideEncryption"] = self._server_side_encryption
            self._client.upload_fileobj(spool, self._bucket, key, ExtraArgs=upload_args)
        return StoredEvidenceObject(self._bucket, key, digest, size_bytes, resolved_media_type)

    def head(self, *, bucket: str, key: str) -> EvidenceObjectHead | None:
        try:
            response = self._client.head_object(Bucket=bucket, Key=key)
        except self._client.exceptions.NoSuchKey:
            return None
        except Exception as exc:
            if _is_missing_object_error(exc):
                return None
            raise EvidenceStoreError("evidence object-store head request failed") from exc
        return EvidenceObjectHead(
            size_bytes=int(response["ContentLength"]),
            media_type=str(response.get("ContentType", "application/octet-stream")),
        )

    def open_stream(self, *, bucket: str, key: str) -> ReadableObject | None:
        try:
            response = self._client.get_object(Bucket=bucket, Key=key)
        except self._client.exceptions.NoSuchKey:
            return None
        except Exception as exc:
            if _is_missing_object_error(exc):
                return None
            raise EvidenceStoreError("evidence object-store read request failed") from exc
        return cast(ReadableObject, response["Body"])

    def create_download_reference(
        self,
        *,
        bucket: str,
        key: str,
        filename: str,
        ttl_seconds: int,
    ) -> DownloadReference:
        ttl = _validated_ttl(ttl_seconds, self._signed_url_ttl_seconds)
        disposition = f'attachment; filename="{safe_download_filename(filename)}"'
        url = self._client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": bucket,
                "Key": key,
                "ResponseContentDisposition": disposition,
            },
            ExpiresIn=ttl,
        )
        return DownloadReference(url, datetime.now(UTC) + timedelta(seconds=ttl), disposition)

    def _copy_and_hash(self, stream: BinaryIO, spool: WritableObject) -> tuple[str, int]:
        digest = hashlib.sha256()
        size_bytes = 0
        while chunk := stream.read(65_536):
            size_bytes += len(chunk)
            if size_bytes > self._max_object_bytes:
                raise EvidenceStoreError("evidence object exceeds configured maximum size")
            digest.update(chunk)
            spool.write(chunk)
        return digest.hexdigest(), size_bytes


class MemoryEvidenceObjectStore:
    """Private in-memory store used only by deterministic offline tests."""

    def __init__(self, *, max_object_bytes: int = 10_485_760) -> None:
        self._max_object_bytes = max_object_bytes
        self._objects: dict[tuple[str, str], tuple[bytes, str]] = {}
        self.download_reference_calls = 0

    def put_stream(
        self,
        *,
        organization_id: UUID,
        evidence_id: UUID,
        collected_at: datetime,
        stream: BinaryIO,
        media_type: str | None,
    ) -> StoredEvidenceObject:
        data = _read_stream_bounded(stream, self._max_object_bytes)
        digest = hashlib.sha256(data).hexdigest()
        key = evidence_object_key(organization_id, evidence_id, collected_at, digest)
        safe_type = safe_media_type(media_type)
        self._objects[("private-evidence", key)] = (data, safe_type)
        return StoredEvidenceObject("private-evidence", key, digest, len(data), safe_type)

    def head(self, *, bucket: str, key: str) -> EvidenceObjectHead | None:
        item = self._objects.get((bucket, key))
        if item is None:
            return None
        data, media_type = item
        return EvidenceObjectHead(len(data), media_type)

    def open_stream(self, *, bucket: str, key: str) -> ReadableObject | None:
        item = self._objects.get((bucket, key))
        if item is None:
            return None
        return io.BytesIO(item[0])

    def create_download_reference(
        self,
        *,
        bucket: str,
        key: str,
        filename: str,
        ttl_seconds: int,
    ) -> DownloadReference:
        if (bucket, key) not in self._objects:
            raise EvidenceStoreError("evidence object is missing")
        ttl = _validated_ttl(ttl_seconds, 300)
        self.download_reference_calls += 1
        disposition = f'attachment; filename="{safe_download_filename(filename)}"'
        return DownloadReference(
            f"memory://private-evidence/{key}",
            datetime.now(UTC) + timedelta(seconds=ttl),
            disposition,
        )

    def replace_for_test(self, *, bucket: str, key: str, data: bytes) -> None:
        _, media_type = self._objects[(bucket, key)]
        self._objects[(bucket, key)] = (data, media_type)

    def remove_for_test(self, *, bucket: str, key: str) -> None:
        self._objects.pop((bucket, key), None)


def evidence_object_key(
    organization_id: UUID,
    evidence_id: UUID,
    collected_at: datetime,
    sha256: str,
) -> str:
    if collected_at.tzinfo is None or collected_at.utcoffset() is None:
        raise EvidenceStoreError("collected_at must be timezone-aware")
    normalized_hash = sha256.lower()
    if _SHA256_PATTERN.fullmatch(normalized_hash) is None:
        raise EvidenceStoreError("evidence SHA-256 must be a lowercase hexadecimal digest")
    observed = collected_at.astimezone(UTC)
    return (
        f"organizations/{organization_id}/evidence/{observed:%Y}/{observed:%m}/"
        f"{evidence_id}/{normalized_hash}"
    )


def safe_media_type(media_type: str | None) -> str:
    if media_type is None:
        return "application/octet-stream"
    normalized = media_type.split(";", maxsplit=1)[0].strip().lower()
    return normalized if normalized in _SAFE_CONTENT_TYPES else "application/octet-stream"


def safe_download_filename(value: str) -> str:
    normalized = _CONTROL_CHARS.sub("", value).replace("/", "_").replace("\\", "_")
    normalized = normalized.replace('"', "_").strip(" .")
    return normalized[:120] or "evidence.bin"


def verify_integrity(store: EvidenceObjectStore, evidence: Evidence) -> IntegrityVerification:
    if evidence.object_store_key is None:
        return IntegrityVerification(
            EvidenceIntegrityStatus.OBJECT_MISSING,
            evidence.sha256,
            None,
            None,
        )
    readable = store.open_stream(bucket=evidence.object_store_bucket, key=evidence.object_store_key)
    if readable is None:
        return IntegrityVerification(
            EvidenceIntegrityStatus.OBJECT_MISSING,
            evidence.sha256,
            None,
            None,
        )
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        while chunk := readable.read(65_536):
            digest.update(chunk)
            size_bytes += len(chunk)
    finally:
        readable.close()
    actual = digest.hexdigest()
    status = EvidenceIntegrityStatus.PASS
    if actual != evidence.sha256 or size_bytes != evidence.size_bytes:
        status = EvidenceIntegrityStatus.HASH_MISMATCH
    return IntegrityVerification(status, evidence.sha256, actual, size_bytes)


@lru_cache
def get_evidence_store() -> EvidenceObjectStore:
    return Boto3EvidenceObjectStore(get_settings())


def _read_stream_bounded(stream: BinaryIO, maximum: int) -> bytes:
    data = bytearray()
    while chunk := stream.read(65_536):
        data.extend(chunk)
        if len(data) > maximum:
            raise EvidenceStoreError("evidence object exceeds configured maximum size")
    return bytes(data)


def _validated_ttl(requested: int, configured: int) -> int:
    if requested < 1 or requested > 300:
        raise EvidenceStoreError("evidence signed URL TTL must be between one and 300 seconds")
    return min(requested, configured, 300)


def _is_missing_object_error(error: Exception) -> bool:
    response = getattr(error, "response", {})
    code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
    return code in {"404", "NoSuchKey", "NoSuchObject", "NotFound"}
