# HTTP Metadata Collection

The HTTP collector uses HEAD first and bounded GET only when required for metadata unavailable from HEAD. It accepts only HTTP/HTTPS URLs with no embedded credentials. It sends transparent `Exposure360/0.1 (+authorized-security-assessment)` identification and minimal safe headers; it never forwards cookies, authorization, browser tokens, or provider credentials.

Responses are streamed under configured connect/read/total timeouts and a strict byte cap. Stored fields are restricted to status, authorized final URL, redirect chain, selected header allowlist, content metadata, sampled-byte count/hash, optional bounded title hint, and truncation indicator. Raw response bodies, Set-Cookie values, and secrets are excluded.

Redirects are manual and capped. Every hop is normalized, must be HTTP/HTTPS, then passes ScopeGuard, policy, address safety, and current authorization before the next request. No recursive crawling, link extraction, path discovery, or automatic redirect following is permitted.
