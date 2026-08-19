# ADR-0005: Target Normalization

One server-side target normalizer owns domain, CIDR/IP, and ASN canonicalization. Domains are IDNA ASCII lowercase names without URL syntax; IP hosts canonicalize to single-host CIDRs; and ASNs canonicalize to `AS<number>`. Global catch-all network seeds are rejected.
