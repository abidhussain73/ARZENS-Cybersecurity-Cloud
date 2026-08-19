# External Reference Notes

## Keycloak protocol mapper reference

Source: [Keycloak Protocol Mappers](https://www.keycloak.org/admin-api/protocol-mappers), accessed 2026-08-19.

The official reference identifies `oidc-sub-mapper` as the built-in OpenID Connect mapper that adds the Subject (`sub`) claim to access tokens. It also identifies `oidc-audience-mapper` as the supported mapper for adding a specified client or custom audience to a token. The local `exposure360-phase1-api` client scope uses these two supported mapper identifiers so the API can validate Keycloak access-token subject and audience through discovery/JWKS.
