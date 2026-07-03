# Security Policy

## Reporting a vulnerability

Email **security@nixfeo.com** with a description, reproduction steps and
impact assessment. Please do not open public issues for security reports.
You will get an acknowledgment within 72 hours.

## Scope

Particularly interesting areas:

- SIP parsing / message construction (rsip fork, sip_builder)
- Digest authentication, nonce handling, the fail2ban path
- TLS (inbound listeners, outbound trunk connections, mTLS)
- SRTP/DTLS key handling
- The management API (auth bypass, injection, SSRF via trunk config)
- The SQLite store (paths, permissions, injection)

## Hardening checklist for deployments

- Bind the management API to localhost or behind a TLS reverse proxy;
  always set a long random `api_auth_token`.
- Keep `security.ban` enabled; whitelist only infrastructure IPs.
- Review `security.destinations` rules for your dial plan (IRSF ranges
  are blocked by default).
- Run as a dedicated user; the SQLite store is created 0600.
- Use real certificates for TLS/WSS listeners and `tls_verify = true`
  (the default) for TLS trunks.
