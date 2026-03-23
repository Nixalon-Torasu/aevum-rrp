v2_84 patch notes (focused)

- Hardened identity private key loading:
  * load_identity_private now tolerates schema drift and path aliases
  * resolves relative private_key_path relative to identity.json
  * falls back to device_ed25519_sk.pem in identity dir
  * derives kid from public key if missing
  * clearer errors for missing/unreadable key file
