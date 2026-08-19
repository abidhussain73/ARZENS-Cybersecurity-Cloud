# ADR-0008: Schedule Timezone Semantics

Scan-policy windows use IANA timezone names. Windows are start-inclusive and end-exclusive. Overnight windows are supported; empty windows mean no time restriction. Invalid timezones and malformed windows fail closed.
