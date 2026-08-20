# Technology Signature Schema

Technology signatures are YAML data under `signatures/technology/{http,tls,service}`. `TechnologySignatureLoader` loads an all-or-nothing ruleset: one invalid YAML rule prevents activation instead of partially changing inference behavior.

```yaml
schema_version: 1
rule_id: tech.example
rule_version: 1
name: Example Technology
technology: { vendor: Example, product: ExampleWeb, category: web_server }
applies_to: [HTTP]
confidence: 0.80
match:
  all:
    - { field: http.headers.server, operator: contains_ci, value: ExampleWeb }
version_extraction:
  field: http.headers.server
  pattern: 'ExampleWeb/(?P<version>[0-9.]+)'
```

Only the documented canonical HTTP, TLS, and service fields and deterministic operators are accepted. Unknown fields, operators, malformed schema, duplicate `rule_id + rule_version`, and unsafe patterns are rejected. Patterns are length-limited, reject backreferences/look-behind and nested quantifiers, compile through the timeout-capable `regex` library, and are tested against bounded input. There is no `eval`, `exec`, shell expression, template expression, or dynamic Python rule execution.

The loader hashes canonical rule content and hashes deterministic ordered rule hashes for the immutable ruleset identifier.
