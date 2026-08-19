from exposure360_api.scope_governance import ScopeConflictAnalyzer, TargetRule, domain_matches


def test_domain_matching_requires_a_label_boundary() -> None:
    assert domain_matches("api.example.com", "example.com", "DOMAIN_AND_SUBDOMAINS")
    assert not domain_matches("evil-example.com", "example.com", "DOMAIN_AND_SUBDOMAINS")


def test_conflict_analyzer_rejects_redundant_network_seed() -> None:
    report = ScopeConflictAnalyzer.analyze(
        [TargetRule("CIDR", "192.0.2.0/24"), TargetRule("CIDR", "192.0.2.128/25")],
        [],
    )
    assert not report.is_approvable
    assert report.errors[0].code == "REDUNDANT"


def test_conflict_analyzer_reports_exclusion_precedence() -> None:
    report = ScopeConflictAnalyzer.analyze(
        [TargetRule("CIDR", "192.0.2.0/24")],
        [TargetRule("CIDR", "192.0.2.50/32")],
    )
    assert report.is_approvable
    assert {finding.code for finding in report.warnings} == {"EXCLUSION_OVERLAPS_SEED"}
