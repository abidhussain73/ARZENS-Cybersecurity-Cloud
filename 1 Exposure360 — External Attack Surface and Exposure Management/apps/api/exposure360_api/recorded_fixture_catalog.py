"""Versioned offline fixtures available only through explicit source references."""

from copy import deepcopy

_PASSIVE_DNS_V1: list[dict[str, object]] = [
    {
        "id": "passive-001",
        "rrname": "www.example.com",
        "rrtype": "A",
        "rdata": "192.0.2.20",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-15T00:00:00Z",
    },
    {
        "id": "passive-002",
        "rrname": "api.example.com",
        "rrtype": "A",
        "rdata": "192.0.2.21",
        "first_seen": "2026-01-02T00:00:00Z",
        "last_seen": "2026-01-15T00:00:00Z",
    },
]

_CERTIFICATE_METADATA_V1: list[dict[str, object]] = [
    {
        "certificate_id": "fixture-cert-001",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2026-04-01T00:00:00Z",
        "subject_cn": "www.example.com",
        "dns_names": ["www.example.com", "api.example.com"],
        "issuer": "Fixture CA",
        "observed_at": "2026-01-15T00:00:00Z",
    }
]


def recorded_fixture(reference: str) -> list[dict[str, object]] | None:
    fixtures: dict[str, list[dict[str, object]]] = {
        "fixture:passive-dns-v1": _PASSIVE_DNS_V1,
        "fixture:certificate-metadata-v1": _CERTIFICATE_METADATA_V1,
    }
    fixture = fixtures.get(reference)
    return deepcopy(fixture) if fixture is not None else None
