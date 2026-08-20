# Identity Key Rules

Canonical keys are deterministic and organization-scoped. The key factory reuses the accepted Phase 2 normalizers for domains and ASNs, while Python address parsing compresses equivalent IPv6 forms.

| Asset | Key form | Example |
|---|---|---|
| Domain | `domain:<fqdn>` | `domain:www.example.com` |
| IP | `ip:<address>` | `ip:192.0.2.20` |
| ASN | `asn:AS<number>` | `asn:AS64500` |
| Endpoint | `endpoint:<transport>:<address>:<port>` | `endpoint:tcp:192.0.2.20:443` |
| IPv6 endpoint | Bracketed IP endpoint form | `endpoint:tcp:[2001:db8::1]:443` |
| Service | Endpoint components, protocol, authority | `service:tcp:192.0.2.20:443:https:www.example.com` |

Certificates, redirects, favicon similarities, names, and ownership are evidence signals only. They never merge canonical assets. Canonical existence is likewise not authorization for future network work; every active request must re-evaluate the existing ScopeGuard authorization.
