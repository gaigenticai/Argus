"""Evidence Vault — S3-compatible blob storage client.

Wraps boto3 to talk to MinIO (default for self-hosted) or any S3 endpoint
(AWS, R2, Backblaze B2). The same client code works for all of them — the
difference is purely the ``endpoint_url`` and addressing style.

Operations are deliberately narrow:
    - ensure_bucket()              create bucket if missing (idempotent)
    - put(key, data, content_type) upload immutable blob
    - get(key) -> bytes            stream blob into memory (callers must
                                    respect size limits at the API layer)
    - presigned_url(key, ttl)      browser-side download URL
    - delete(key)                  hard-delete object (used only by
                                    retention worker)
    - exists(key) -> bool

This module intentionally does **not** know about Postgres. The
:class:`EvidenceBlob` row is the source of truth for "does this blob exist
logically"; ``exists()`` here only checks physical S3 state. Reconciling
the two is a job for the retention worker.
"""

from __future__ import annotations

import hashlib
import io
import logging
from contextlib import contextmanager
from typing import Iterator

import boto3
from boto3.session import Session
from botocore.client import Config as BotoConfig
from botocore.exceptions import ClientError

from src.config.settings import settings


_logger = logging.getLogger(__name__)


def _make_client():
    """Build an S3 client configured for the current evidence settings."""
    cfg = settings.evidence
    boto_cfg = BotoConfig(
        signature_version="s3v4",
        s3={"addressing_style": "path" if cfg.use_path_style else "auto"},
        retries={"max_attempts": 5, "mode": "standard"},
        connect_timeout=10,
        read_timeout=60,
    )
    sess = Session(
        aws_access_key_id=cfg.access_key,
        aws_secret_access_key=cfg.secret_key,
        region_name=cfg.region,
    )
    return sess.client(
        "s3",
        endpoint_url=cfg.endpoint_url,
        config=boto_cfg,
    )


# Lazy singleton — one client per process.
_client = None


def get_client():
    global _client
    if _client is None:
        _client = _make_client()
    return _client


def reset_client() -> None:
    """Reset the cached client. Used by tests when settings change."""
    global _client
    _client = None


def ensure_bucket(bucket: str | None = None) -> None:
    """Create the bucket if it doesn't exist. Idempotent."""
    bucket = bucket or settings.evidence.bucket
    client = get_client()
    try:
        client.head_bucket(Bucket=bucket)
        return
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code not in ("404", "NoSuchBucket", "NotFound"):
            raise
    # Region must be omitted for us-east-1 in AWS, but MinIO accepts both.
    region = settings.evidence.region
    if region == "us-east-1":
        client.create_bucket(Bucket=bucket)
    else:
        client.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    _logger.info("Created evidence bucket %s", bucket)


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def storage_key(organization_id: str, sha256: str) -> str:
    """Canonical S3 key for an evidence blob.

    Layout: ``<org_id>/<aa>/<sha256>`` — the two-char shard prefix avoids
    flat-namespace performance issues on large tenants and matches the
    layout most CDN providers prefer.
    """
    return f"{organization_id}/{sha256[:2]}/{sha256}"


def put(
    bucket: str,
    key: str,
    data: bytes,
    content_type: str,
    metadata: dict[str, str] | None = None,
) -> None:
    """Upload a blob. Immutable — overwrites are forbidden by convention."""
    client = get_client()
    extra: dict = {"ContentType": content_type}
    if metadata:
        extra["Metadata"] = {k: str(v) for k, v in metadata.items()}
    client.put_object(Bucket=bucket, Key=key, Body=data, **extra)


def get(bucket: str, key: str) -> bytes:
    client = get_client()
    obj = client.get_object(Bucket=bucket, Key=key)
    return obj["Body"].read()


def exists(bucket: str, key: str) -> bool:
    client = get_client()
    try:
        client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
            return False
        raise


def delete(bucket: str, key: str) -> None:
    client = get_client()
    client.delete_object(Bucket=bucket, Key=key)


def presigned_get_url(bucket: str, key: str, ttl_seconds: int | None = None) -> str:
    client = get_client()
    return client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=ttl_seconds or settings.evidence.signed_url_ttl_seconds,
    )


@contextmanager
def stream(bucket: str, key: str) -> Iterator[io.IOBase]:
    """Yield a file-like stream over the object body."""
    client = get_client()
    obj = client.get_object(Bucket=bucket, Key=key)
    try:
        yield obj["Body"]
    finally:
        try:
            obj["Body"].close()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass


__all__ = [
    "ensure_bucket",
    "get_client",
    "reset_client",
    "sha256_of",
    "storage_key",
    "put",
    "get",
    "exists",
    "delete",
    "presigned_get_url",
    "stream",
]
