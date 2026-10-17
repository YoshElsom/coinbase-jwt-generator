# Coinbase integration security status

This repository preserves the Coinbase JWT signing helper for future backend use.
The unauthenticated token endpoint and CLI token printing are intentionally disabled.

## Immediate owner action

Revoke the Coinbase API credential previously embedded in this repository.
Treat it as compromised: source history and third-party copies may contain it.
No claim is made that the credential has been revoked, history purged, or a deployed service updated.

## Current behavior

- GET /healthz returns a non-sensitive health response.
- /generate-jwt returns HTTP 410 for every method, regardless of supplied credentials.
- Other HTTP paths return 404. The HTTP process never loads exchange credentials.
- generateCoinbaseJWT is an internal module accepting only explicitly allowed GET paths.
- Keys come from COINBASE_API_KEY_NAME and COINBASE_API_PRIVATE_KEY.
- Only ECDSA P-256 keys are accepted. Signing uses native Node crypto with ES256's 64-byte P1363 signature.
- Tokens expire after 120 seconds, bind the method/host/path, and include a fresh random nonce.
- No Coinbase requests or trades are performed by this code.
- Run npm test using Node 22 or newer. Tests use ephemeral locally generated keys.

## Runtime configuration

For a future trusted backend, supply newly issued read-only Coinbase credentials through protected
runtime settings or a secret manager. Do not commit keys, .env files, generated tokens or Render secret values.
For a Render web service, HOST=0.0.0.0 and the platform-supplied PORT configure the containment server;
no Render configuration or deployment has been changed by this patch.

Do not restore the public token endpoint. A future integration must authenticate callers, authorize
the requested portfolio, perform approved reads server-side and return sanitized data rather than JWTs.

## Preservation and remaining work

The prior code remains in Git history. No force push, history rewrite or repository deletion was performed.
Rolling back the original source would reintroduce exposed credentials and public token minting; preserve
the implementation reference without redeploying that unsafe state.
Tracked historical node_modules and metadata remain in the repository; .gitignore prevents new untracked
copies but does not remove already tracked files.

Repository visibility is a separate owner decision. Private visibility does not invalidate leaked keys.
Review known deployments and third-party copies, revoke the exposed credential, and verify any running
service uses the containment release before considering the incident contained.
