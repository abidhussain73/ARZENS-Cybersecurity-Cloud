# TLS Metadata Collection

TLS collection runs only after guarded TCP eligibility and a second operation-level `ScopeGuard` decision. It uses a standard client, configured handshake timeout, and authorized hostname SNI where relevant. It sends no credentials, client certificates, or application payloads.

Collected metadata is bounded to negotiated TLS version/cipher/ALPN, leaf fingerprint, subject, issuer, serial, validity dates, SAN DNS names, chain length when safely available, handshake duration, and validation status. Metadata observation mode may record expired, self-signed, or hostname-invalid certificates, but successful socket establishment is never treated as trust. Private keys, session tickets, and raw secrets are not retained.

Fixture tests verify deterministic fingerprint/SAN metadata, timeout classification, validation status, and zero transport calls for denied targets.
