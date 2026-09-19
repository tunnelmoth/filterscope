# Security

## What filterscope does on your machine

- It opens outbound connections (DNS, TLS, HTTP, UDP) to a fixed list of well-known public sites and to public test endpoints. It never requests inappropriate content. It sends no data anywhere. There is no account, no telemetry and no reporting server.
- It writes reports and a history under `~/.filterscope/`. On Android it uses the app's private files directory.
- The Tor probe starts a local `tor` process with a temporary data directory and `SocksPort 0`. The process is killed when the probe ends.
- `filterscope warp` (Linux only, an explicit command) installs Cloudflare WARP and uses `sudo` to bring a WireGuard interface up. Downloads are verified: wgcf against the release file `checksums.txt`, the WARP `.deb` against the apt `Release` signature (when `gpgv` is present) and its SHA256 chain. Nothing is piped to a shell.

## Design decisions

- Two TLS handshakes per site run without certificate verification on purpose. The SNI probe only observes whether the handshake is reset. The second handshake of the TLS-interception probe only reads the certificate that the network presented. No data is exchanged over those sessions. All other TLS (DoH, DoT, throughput, the first interception handshake) verifies against the Mozilla CA bundle (certifi).
- Plain HTTP requests detect block pages and transparent proxies. Bodies are cut at 8 KB and are never executed or rendered.
- User-supplied labels are sanitized before they become file names. Network-derived strings are escaped before they reach the terminal renderer or the HTML report.

## Binaries and signing

- GitHub Actions builds the desktop binaries from the tagged source. They are not code-signed. Verify each SHA-256 against `SHA256SUMS.txt` from the same release.
- The Android APK is signed with a key that lives in this repository (`android/keystore/`), so that sideloaded updates install over each other. That key proves nothing about the author. The release page and its checksums are the trust root.
- GitHub Actions are pinned to commit hashes.

## Reporting

Open an issue at https://github.com/tunnelmoth/filterscope/issues. For a sensitive report, open a minimal issue first and ask for a contact channel.
