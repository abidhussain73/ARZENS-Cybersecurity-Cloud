import pytest

from exposure360_api.scope_governance import ScopeTargetNormalizer, ScopeValidationError


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("EXAMPLE.COM", "example.com"),
        ("example.com.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_domain_normalization_is_deterministic(raw: str, canonical: str) -> None:
    assert ScopeTargetNormalizer.normalize_domain(raw).canonical_value == canonical


@pytest.mark.parametrize(
    "raw",
    ["https://example.com", "example.com/path", "", "bad_domain.example", "example.com\x00"],
)
def test_domain_normalization_rejects_ambiguous_input(raw: str) -> None:
    with pytest.raises(ScopeValidationError):
        ScopeTargetNormalizer.normalize_domain(raw)


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("192.0.2.1/24", "192.0.2.0/24"),
        ("192.0.2.1/32", "192.0.2.1/32"),
        ("2001:db8::1/128", "2001:db8::1/128"),
    ],
)
def test_cidr_normalization_is_deterministic(raw: str, canonical: str) -> None:
    assert ScopeTargetNormalizer.normalize_network(raw).canonical_value == canonical


@pytest.mark.parametrize("raw", ["0.0.0.0/0", "::/0", "999.1.1.1/24", "192.0.2.0/33"])
def test_cidr_normalization_rejects_unsafe_or_invalid_networks(raw: str) -> None:
    with pytest.raises(ScopeValidationError):
        ScopeTargetNormalizer.normalize_network(raw)


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [("AS64500", "AS64500"), ("64500", "AS64500"), ("as64500", "AS64500")],
)
def test_asn_normalization_is_deterministic(raw: str, canonical: str) -> None:
    assert ScopeTargetNormalizer.normalize_asn(raw).canonical_value == canonical


@pytest.mark.parametrize("raw", ["ASABC", "-1", "4294967296"])
def test_asn_normalization_rejects_invalid_values(raw: str) -> None:
    with pytest.raises(ScopeValidationError):
        ScopeTargetNormalizer.normalize_asn(raw)
