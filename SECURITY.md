# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's
private vulnerability reporting for this repository ("Report a vulnerability"
under the Security tab). If that option is unavailable, email
[security@githits.com](mailto:security@githits.com), the contact published in
[GitHits' security reporting guidance](https://githits.com/legal/terms-of-service/).
Include the affected version, impact, and a minimal reproduction without tokens
or private repository contents. We acknowledge reports within five business days.

## What the tool handles

`githits-scan` reads one credential, `GITHITS_API_TOKEN`, and uploads
repository files to the GitHits API. The rules it follows are part of the
contract, not incidental:

- The token is accepted only from the environment, never from a flag, and
  never appears in output, `Debug` formatting, or error messages.
- Only cataloged lockfiles and manifests leave the machine. `detect` lists
  candidates and configured selections; upload preparation may additionally
  select eligible Cargo/npm workspace member manifests. File contents are sent
  in full, without redaction. See [README privacy](README.md#privacy-and-uploaded-data).
- Requests go only to `https://api.githits.dev` or the HTTPS origin in
  `GITHITS_API_URL` (plain HTTP is allowed for loopback hosts only), and
  redirects are never followed.
- Response bodies are read with fixed size caps.

If you find behavior that contradicts any of these, that is a vulnerability
in this tool and we want to hear about it.

## Supported versions

Only the latest release receives fixes.
