# Experimental organisation OIDC integration

Only the local Keycloak configuration has been tested. No corporate identity system has been contacted or configured.

An IT administrator should:

1. Approve the issuer URL, discovery/JWKS endpoints, and the network path from developers and the backend. Developers must reach the devctl gateway; the backend must reach each registered Kubernetes API, potentially through the VPN. Use verified HTTPS, including private CA trust where required. Confirm the provider issues signed JWT **access tokens**, with a stable issuer and subject. Opaque tokens and SAML are unsupported.
2. Register a **public native CLI client**, enable Authorization Code flow with mandatory PKCE S256, and disable password grant. No client secret is embedded or required. Approve the exact loopback redirect `http://127.0.0.1:18000/callback`, or configure another approved fixed local port on both sides. The CLI binds only IPv4 loopback, validates state, and checks the ID token signature, issuer, client audience, expiry, and nonce.
3. Register the backend API audience/resource used by both the reservation API and Kubernetes gateway. Make sure the CLI's **access token** includes that API audience. The ID token is for the CLI and must not be accepted as API authorization. Configure an explicit access-token marker, for example Keycloak payload `typ=Bearer` or a provider's `token_use=access`, which ID tokens do not have.
4. Configure a group or role claim as a JSON array of strings. Provision approved developer and administrator groups. A dotted claim path such as `realm_access.roles` is supported. Group mapping is trusted configuration, never a request-body permission. Make sure the access token includes a nonempty `sub`; Keycloak's `basic` client scope provides this in the supplied realm.
5. Request `openid profile email` scopes plus any API-specific provider scope. Confirm display name/username and email contact visibility is approved for the whole team. Ownership uses issuer plus subject, not email. The backend never identifies ownership by a user-supplied name.
6. Enable refresh tokens for a public client and confirm its rotation, lifetime, and revocation semantics. The standard Keycloak browser flow supplies refresh tokens without `offline_access`; requesting offline tokens requires explicit provider/user permissions and is optional. Configure the OS credential store for developer machines. The file fallback must be explicitly enabled only for development.
7. Configure both backend and CLI with matching issuer/client/claim settings. Set the developer-facing HTTPS `DEVCTL_PUBLIC_URL` and optional public gateway CA bundle on the backend, and set `DEVCTL_API_CA_FILE` on the CLI for a private backend CA; generated gateway kubeconfigs contain public connection metadata and a devctl credential-plugin invocation, never original cluster credentials. Run login, whoami, expiry, refresh, logout, wrong-audience, wrong-issuer, ID-token rejection, and unapproved-user checks in an approved staging environment. Verify tokens are absent from logs.
8. Confirm that logout releases all devctl bookings for the identity, clears local login, and attempts provider-advertised refresh-token revocation. It does not necessarily end the browser's SSO session or revoke previously issued access tokens. Gateway requests for a released session are denied even if a client retains its OIDC token; ongoing streams are terminated after backend revalidation. Separately, this does not revoke legacy original Kubernetes credentials held outside the gateway.

Example shared environment configuration (use actual approved values):

```bash
export DEVCTL_ISSUER='https://identity.example.test/realms/engineering'
export DEVCTL_OIDC_CONFIG='{
  "issuer": "https://identity.example.test/realms/engineering",
  "client_id": "devctl-cli",
  "audience": "devctl-api",
  "scopes": ["openid", "profile", "email"],
  "redirect": "http://127.0.0.1:18000/callback",
  "groups_claim": "groups",
  "developer_group": "/developers",
  "admin_group": "/administrators",
  "access_claim": "typ",
  "access_value": "Bearer"
}'
export DEVCTL_API='https://devctl.example.test'
# If the gateway uses a private CA not already trusted by the OS:
# export DEVCTL_API_CA_FILE='/path/to/public-devctl-ca.pem'
unset DEVCTL_DEV_HTTP DEVCTL_DEV_TOKEN_FILE
```

`DEVCTL_OIDC_CONFIG` overrides the default fields. For role-based providers, set `groups_claim`, `developer_group` and `admin_group` to the approved role claim/path and values. Provider-specific audience/scope setup is an IT task; do not turn off audience, signature, expiry, issuer, nonce, or group validation to work around a mismatch.

Cluster API servers do not need to trust the organisation's OIDC issuer. The devctl credential plugin returns an API-audience access token to local kubectl, which connects to the authenticated gateway. The gateway validates that token and the active owned reservation, then uses its server-held Kubernetes credentials for the upstream request. It does not forward the developer's token or introduce Kubernetes impersonation. An ID token is not accepted as gateway authorization.

IT should test stop/logout/expiry against a copied gateway-only kubeconfig and a retained OIDC access token, including an open streaming connection. Distinguish blocking new gateway use and closing existing streams from revoking legacy direct Kubernetes credentials. Original configurations distributed outside the gateway still bypass reservations. Existing Kubernetes permissions and workload cleanup are unchanged; a privileged identity can access other credentials through its allowed API operations.
