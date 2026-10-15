# Security policy

## Supported versions

Quayel Gateway is pre-1.0. Security fixes go into the latest minor release
only, so please upgrade to the newest version before reporting.

| Version | Supported |
|---------|-----------|
| 0.6.x   | Yes       |
| < 0.6   | No        |

## Reporting a vulnerability

**Please don't open a public issue for security problems.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/quayel/Quayel-Gateway/security/advisories/new)
(Security tab → *Report a vulnerability*).

Please include:

- the version (`quayel-gateway --version`) and how you run it (Docker, `.deb`, binary),
- the relevant part of your `config.json`, with secrets removed,
- steps to reproduce, and what an attacker can achieve.

We aim to acknowledge reports within 3 working days and to ship a fix or a
mitigation for confirmed issues as quickly as their severity requires. We'll
keep you updated, credit you in the release notes if you'd like, and publish
a GitHub security advisory once a fixed release is out.

## Scope

In scope: the gateway binary, the Docker image, the `.deb` package and the
default configs in this repository. Examples: bypassing firewall or rate-limit
rules, spoofing the client IP from an untrusted peer, forging verified JWT
claims, crashing the gateway with crafted input, reading other visitors'
cached responses, or getting a certificate issued for a domain not in
`auto_ssl.domains`.

Out of scope: volumetric DDoS that fills the network link (no server can stop
it; see the docs), issues that need an attacker to already control
`config.json` or the host, and findings in third-party IP datasets.
