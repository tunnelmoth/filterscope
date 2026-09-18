# filterscope

Measure the **filtering / censorship** behaviour of the network you are on — legitimately, with your own traffic. For digital rights and transparency, in the spirit of EFF and Tor.

> Run it only **from your own device, with your own traffic**. filterscope uses a **clean allowlist** (well-known news / social / privacy / dev / education sites) — it never touches inappropriate or illegal content. That is a deliberate choice to avoid the controversial-domain problem of global test lists.

Works on **Linux, Windows and macOS**. Single-file binaries on the [releases page](https://github.com/tunnelmoth/filterscope/releases); or `pip install`.

## What it measures

| Probe | How |
|---|---|
| **DNS tampering / hijack** | System resolver and direct `@8.8.8.8` are compared with DoH as the reference. Only private-IP redirection and NXDOMAIN injection are flagged; a mere IP difference is treated as CDN (low false-positive rate). |
| **TLS / SNI blocking (DPI)** | TLS to the real IP with the real server name vs. a harmless control name. Reset/timeout only with the real name = SNI-based deep packet inspection. |
| **In-path RST injection** | Time-to-RST is compared with the TCP round trip. An RST that arrives faster than a round trip was injected by a middlebox, not sent by the server. |
| **Block page** | Signatures of BTK/5651, FortiGuard, Sophos, Squid, Cisco Umbrella, Lightspeed, Securly, GoGuardian, Netsweeper, Smoothwall, Palo Alto, Zscaler, Forcepoint, Barracuda… |
| **Outbound TCP ports** | Via `portquiz.net` (listens on every port). `timeout` = packets dropped (real block); `refused`/`RST` = the packet got out. |
| **UDP egress** | STUN binding requests to several servers/ports (indicator for WireGuard / IPsec). |
| **QUIC / UDP-443** | A QUIC version-negotiation probe (RFC 9000 §6) to Cloudflare and Google — no crypto, unambiguous. Tells you if HTTP/3 and QUIC tunnels can leave the network. |
| **Encrypted DNS** | Is DoH (Cloudflare, Google, AdGuard) / DoT (Cloudflare, Google, Quad9) itself reachable. |
| **Port-53 interception** | A plain DNS query is sent to `192.0.2.1` (TEST-NET-1, cannot run a resolver). Any answer proves the network transparently proxies DNS — "just use 8.8.8.8" does nothing there. |
| **HTTP transparent proxy** | Filter-appliance headers (`Via`, `X-Squid-*`, BlueCoat, FortiGate, Sophos…) on a neutral plain-HTTP fetch. |
| **ECH / encrypted SNI** | Does the site publish `ech` in its HTTPS record? Combined with SNI-DPI detection it infers "this block is bypassable with ECH". |
| **IPv6 egress**, **SSH egress**, **throughput** (`--speed`) | |
| **VPN diagnosis** | Are VPN sites/APIs (Proton, Mullvad, Nord, Windscribe, AirVPN) blocked at the SNI layer — explains why an app fails at login, and what to do. |
| **Tor** | A real `tor` bootstrap to 100 %. |

Every finding feeds a **VPN diagnosis** and a **tunnel / circumvention** advice block, plus an evidence trail (JSON, anonymized JSON, HTML, time-series history).

## Install

**Binary** (no Python needed): download `filterscope-windows-x86_64.exe`, `filterscope-linux-x86_64`, `filterscope-macos-arm64` or `filterscope-macos-x86_64` from [releases](https://github.com/tunnelmoth/filterscope/releases). Verify with `SHA256SUMS.txt`.

**Python** (3.10+):

```bash
pipx install git+https://github.com/tunnelmoth/filterscope     # or: pip install --user .
```

The Tor test needs a `tor` binary: `apt/pacman/brew install tor`, or on Windows the [Tor Expert Bundle](https://www.torproject.org/download/tor/) (`tor.exe` on PATH, next to the exe, or an installed Tor Browser is found automatically).

## Usage

```bash
filterscope                                  # live TUI dashboard (r rescan, t Tor, s save, q quit)
filterscope scan                             # full CLI scan; exit code 2 if interference found
filterscope scan --quick                     # sites + ports + UDP + DNS only, no Tor/ECH/block-page
filterscope scan --categories ai,vpn-api     # scope to categories (filterscope categories lists them)
filterscope scan --domain example.org        # add your own domains (--domains-file too)
filterscope scan --label school --json school.json --html school.html
filterscope scan --anon-json share.json      # PII-free shareable report
filterscope scan --speed                     # also measure downstream throughput
filterscope report school.json               # re-render a saved JSON (or --html out.html)
```

### Evidence: two networks, one diff

```bash
filterscope scan --label school --json school.json
filterscope scan --label mobile --json mobile.json    # after switching to mobile data
filterscope compare school.json mobile.json
```

Anything blocked on one network but open on the other is filtering **specific to that network**.

### Evidence over time

Every scan appends a compact record to `~/.filterscope/history.jsonl`.

```cron
*/30 * * * * filterscope scan --no-tor --label school --quiet >> ~/.filterscope/run.log 2>&1
```

```bash
filterscope history                          # timeline + "new block / lifted" per network
filterscope history --network school --last 10
```

### Does my VPN work here?

```bash
filterscope wg --config /etc/wireguard/wg0.conf      # real WireGuard handshake (Noise_IKpsk2) to YOUR server
```

### Bypass with Cloudflare WARP (Linux)

```bash
filterscope warp test          # reachable on this network?
filterscope warp up            # WireGuard tunnel (sudo); automatic port search if no data flows
filterscope warp masque up     # official client in MASQUE/HTTP3 mode when WireGuard is throttled
filterscope warp status / down
```

On Windows and macOS use the official 1.1.1.1 app and pick MASQUE in its settings.

## Interpreting results

- **SNI-DPI** — the network reads the server name in the TLS ClientHello and resets specific sites. Application-layer content filter. If the note says *in-path injection*, the RST came from a middlebox, not the server.
- **HIJACK-blockpage** — DNS answers with a private/local IP (a block-page server).
- **DNS-BLOCK** — the local resolver returns nothing while DoH resolves.
- **INTERCEPTED** (port 53) — the network answers DNS on behalf of every address; changing your resolver to 8.8.8.8 is ignored.
- **BLOCKED** on DoH/DoT — encrypted DNS is blocked; apps using it (Firefox DoH, Android Private DNS) fail.
- **BLOCKED** on a port / QUIC / UDP — packets to that port are dropped.
- **PROXY** — a transparent HTTP proxy or filter appliance is rewriting plain HTTP.

To argue that filtering is improper: keep the timestamped JSON, run the same scan on **a different network** and show the diff. The HTML report is self-contained and printable.

## JSON schema

`schema: 2`. Top level: `ts`, `version`, `net` (id/label/ssid/gateway/resolver/os), `sites{domain: {cat, dns, sni, blockpage, ech}}`, `ports`, `udp`, `udp_detail`, `quic`, `quic_detail`, `ipv6`, `dns_encrypted`, `dns_intercept`, `http_proxy`, `ssh`, `tor`, `speed`, `flagged[]`. The anonymized variant drops `net.*` except id/label, resolver answers and proxy headers.

## Development

```bash
pip install -e ".[dev]"
pytest                                  # offline unit tests
pyinstaller packaging/filterscope.spec  # single-file binary → dist/
```

CI runs the tests on Linux, Windows and macOS; a `v*` tag builds and publishes the binaries.

## Roadmap

- [x] Evidence mode: time-series + change tracking
- [x] Network comparison, anonymized reports, HTML report
- [x] ECH detection + bypass inference, real WireGuard handshake test
- [x] Encrypted DNS, DNS interception, QUIC, transparent proxy, RST injection timing
- [x] Windows / macOS, single-file binaries
- [ ] DoQ (DNS over QUIC) and HTTP/3 page fetch
- [ ] Opt-in anonymous aggregate report server

## License

GPL-3.0-or-later. Free software — use it, study it, modify it, share it.
