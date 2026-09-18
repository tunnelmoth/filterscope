# Security

## What filterscope does on your machine

- Opens outbound connections (DNS, TLS, HTTP, UDP) to a fixed list of well-known public sites and
  public test endpoints. It never asks for inappropriate content and never sends your data anywhere:
  there is no account, no telemetry, no reporting server.
- Writes reports and a history under `~/.filterscope/` (on Android: the app's private files dir).
- Optionally starts a local `tor` process for the Tor bootstrap probe (temporary data directory,
  SocksPort 0, killed when the probe ends).
- `filterscope warp` (Linux only, explicit command) installs Cloudflare WARP and uses `sudo` to
  bring a WireGuard interface up. Downloads are verified: wgcf against the release's
  `checksums.txt`, the WARP `.deb` against the apt `Release` signature (when `gpgv` is present)
  and its SHA256 chain. Nothing is piped to a shell.

## Deliberate design choices

- Two TLS handshakes are made **without** certificate verification on purpose: the SNI probe
  (we only care whether the handshake is reset) and the second handshake of the TLS-interception
  probe (to read the certificate the network presented). No data is exchanged over those sessions.
  All other TLS (DoH, DoT, throughput, the first interception handshake) verifies against the
  Mozilla CA bundle (certifi).
- Plain HTTP (`http://`) requests are made to detect block pages and transparent proxies. Bodies are
  truncated to 8 KB and never executed or rendered.
- User-supplied labels are sanitized before they become file names; network-derived strings are
  escaped before they reach the terminal renderer or the HTML report.

## Binaries and signing

- Desktop binaries are built by GitHub Actions from the tagged source and are **not code-signed**.
  Verify SHA-256 against `SHA256SUMS.txt` from the same release.
- The Android APK is signed with a key that lives in this repository (`android/keystore/`), so
  sideloaded updates install over each other. That key proves nothing about the author; the
  release page and its checksums are the trust root.
- GitHub Actions are pinned to commit SHAs.

## Reporting

Open an issue at https://github.com/tunnelmoth/filterscope/issues. For anything sensitive, open a
minimal issue asking for a contact channel first.
