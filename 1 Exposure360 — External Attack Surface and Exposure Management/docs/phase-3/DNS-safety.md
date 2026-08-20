# DNS Collection Safety

DNS validation queries only existing, normalized `DOMAIN` candidates or approved seeds after a `ScopeGuard` allow decision. Phase 3 limits validation to A and AAAA records, with optional bounded CNAME metadata. It performs no wordlist generation, AXFR, ANY query, DNSSEC attack testing, or recursive enumeration.

The resolver interface is injected. Production resolution is bounded by configured timeout, lifetime, answer count, and CNAME depth. Tests use deterministic fixtures. NXDOMAIN and no-answer are collection results, not worker crashes.

Resolved addresses are classified before downstream work. Loopback, unspecified, private, link-local, multicast, carrier-grade, metadata-service, and other non-global addresses are retained as DNS observations but are not scheduled for TCP/TLS/HTTP by default. Downstream collectors use recently validated address information and recheck rather than allowing an HTTP client to independently resolve an unverified address.

