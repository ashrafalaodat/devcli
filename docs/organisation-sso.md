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
8. Confirm that logout releases all devctl bookings for the identity, clears local login, and attempts provider-advertised OAuth refresh-token revocation. PATs remain valid until expiry or explicit revocation; they regain gateway access only after a new explicit booking. It does not necessarily end the browser's SSO session or revoke previously issued access tokens. Requests for an ended reservation are denied even if a client retains its OIDC token; if another owned booking remains, the oldest becomes primary. Ongoing streams for the old selection are terminated after backend revalidation. Separately, this does not revoke legacy original Kubernetes credentials held outside the gateway.
9. For CLI/plugin token refresh, approve refresh-token rotation and both idle and absolute session limits. New demo realms use ten-minute access tokens, one day of SSO inactivity, and a seven-day absolute session maximum. Existing persistent Keycloak realms are not overwritten by startup imports: update those policy values through provider administration if desired. Test concurrent refreshes and rotation under the actual provider. Kubernetes activity permits the helper to renew authentication within provider limits. Separately, authenticated requests/open streams extend only the current reservation’s inactivity deadline; the token-refresh heartbeat itself does not. An idle browser tab does not keep bookings reserved, and scripts/watches are not proof of human presence. Test a long-running connection across a fresh-token heartbeat and confirm stop/logout/expiry still close it.
10. Register a separate browser client (`devctl-web` by default), with Authorization Code, mandatory PKCE S256, the same API audience and group mapper, and an exact redirect such as `https://devctl.example.test/auth/callback`. The local demo redirect is `https://127.0.0.1:9090/auth/callback`. Set `DEVCTL_WEB_CLIENT_ID` and, if the organisation requires a confidential web client, `DEVCTL_WEB_CLIENT_SECRET` on the backend only. Never add that secret to CLI/plugin configuration. Configure private CA trust in the browser and use the exact public origin; cookie mutations validate Origin. Approve `DEVCTL_WEB_SESSION_TTL` (default 8h absolute).
11. Review browser-issued PAT policy separately from OAuth refresh policy. PATs are gateway-only, scoped to the developer’s current primary cluster, individually revocable and valid for 8h by default (maximum 168h, independent of booking expiry). They have no refresh token and do not renew themselves. Their purpose is native kubectl access without installing a helper. A provider account/group removal does not directly revoke existing PATs: include application-side PAT revocation and booking release in the offboarding checklist. The UI's administrator credential view and audit list support this process. A PAT remains valid after ending a booking or logging out and can access a later explicitly booked primary until the PAT itself expires or is explicitly revoked. Logout does not replace the application-side PAT revocation step during offboarding.

The plugin uses the same approved native client, credential store, refresh locking and rotation as the full CLI. Its smaller command set is a user-interface choice, not a new security role: authorization always comes from validated provider claims on the backend. Browser administration uses SSO; a downloaded PAT cannot authorize an admin action.

For an existing persistent local Keycloak realm, sign into the development admin console and import `deploy/keycloak-web-client.json` under **Clients → Import client**. This adds the browser client without recreating the realm, changing user subjects, or losing reservations. Fresh demo realms include the client automatically. Do not delete identity-provider or PostgreSQL volumes to add this client.

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
export DEVCTL_WEB_CLIENT_ID='devctl-web' # backend
export DEVCTL_WEB_SESSION_TTL='8h'       # backend
# If the gateway uses a private CA not already trusted by the OS:
# export DEVCTL_API_CA_FILE='/path/to/public-devctl-ca.pem'
unset DEVCTL_DEV_HTTP DEVCTL_DEV_TOKEN_FILE
```

`DEVCTL_OIDC_CONFIG` overrides the default fields. For role-based providers, set `groups_claim`, `developer_group` and `admin_group` to the approved role claim/path and values. Provider-specific audience/scope setup is an IT task; do not turn off audience, signature, expiry, issuer, nonce, or group validation to work around a mismatch.

Cluster API servers do not need to trust the organisation's OIDC issuer. The devctl credential plugin returns an API-audience access token to local kubectl, which connects to the authenticated gateway. The stable /k8s gateway validates that token, resolves the developer’s current primary, and checks the active owned reservation before using its server-held Kubernetes credentials. It does not forward the developer's token or introduce Kubernetes impersonation. An ID token is not accepted as gateway authorization.

IT should set the administrator inactivity period (default 4h), then test per-cluster activity, idle tabs/polling, expiry with clients closed, default/per-user booking limits, primary switching, stop/logout/expiry and PAT revocation against a copied stable gateway kubeconfig, including an open streaming connection. Distinguish blocking new gateway use and closing existing streams from revoking legacy direct Kubernetes credentials. Original configurations distributed outside the gateway still bypass reservations. Existing Kubernetes permissions and workload cleanup are unchanged; a privileged identity can access other credentials through its allowed API operations.

The administrator-controlled booking limit defaults to one and is independent of provider group roles. Approved administrators may configure a global default and individual overrides. Ownership and selection are issuer/subject-wide across clients; separate local profiles do not create independent primary selections. Login/setup/token refresh never books a cluster. Without an active primary, the gateway returns “no cluster is booked.” Changing primary closes old streams and affects subsequent commands without a kubeconfig change. Legacy session-scoped PATs are revoked during migration and require one replacement download.

Reservation inactivity and identity-provider session lifetimes are separate controls. Booking duration/manual lease renewal are retired. Use `devctl admin settings --inactive-grace 4h --reason 'Approved inactivity policy'` or the browser administration form; the range is 1m through 168h. Changes apply to current bookings and can release already-idle reservations when shortened. Inactivity release leaves PATs and Kubernetes workloads intact; it prevents gateway access until another explicit booking. Existing active bookings receive one grace window during upgrade. Test the resulting workload handover and offboarding process in approved staging.
