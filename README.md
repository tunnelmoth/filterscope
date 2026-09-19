# filterscope

filterscope measures the filtering on the network you are connected to. It uses your own device and your own traffic. It sends requests only to well-known public sites and to public test endpoints. It never requests inappropriate content. The result is a score, the list of techniques the network uses and advice in plain language.

Website and downloads: https://tunnelmoth.github.io/filterscope/
Current stable version: 3.6.126. License: GPL-3.0-or-later.

filterscope runs on Windows and Android, and also on Linux and macOS. The engine is one Python package, so the desktop window, the terminal dashboard, the command line and the Android app all give the same result.

## What it measures

Every scan runs about 16 probe types over 279 sites in 27 categories. A full scan takes roughly 60 s to 90 s on a normal connection, and we expect it to take longer on a network that drops packets, because each dropped connection waits for its timeout.

| Probe | Method |
|---|---|
| DNS tampering | The system resolver and a direct query to 8.8.8.8 are compared with DNS over HTTPS. Only a private-IP answer or a withheld answer counts. A different public IP is treated as a CDN. |
| TLS server-name inspection (SNI-DPI) | A TLS handshake to the real IP with the real name, then one with a harmless name. A reset only with the real name means the network reads the ClientHello. |
| In-path RST injection | The time to the reset is compared with the TCP round trip. A reset that arrives faster than one round trip almost certainly came from a middlebox. |
| TLS interception | Verified handshakes against the Mozilla CA bundle for 4 large sites. A chain signed by a private issuer means the network decrypts HTTPS. |
| Block page | Signatures of filter products (FortiGuard, Sophos, Squid, Cisco Umbrella, Lightspeed, Securly, Netsweeper, Palo Alto, Zscaler, BTK/5651 and more). Generic wording counts only on a plain-HTTP answer. |
| Outbound TCP ports | A TCP connect to portquiz.net on 9 ports. A timeout means dropped packets. A refusal means the packet got out. |
| UDP egress | STUN binding requests to 4 servers. |
| QUIC / UDP 443 | A QUIC version-negotiation packet to Cloudflare and Google (RFC 9000, section 6). |
| Encrypted DNS | DoH to Cloudflare, Google and AdGuard. DoT to Cloudflare, Google and Quad9. |
| Port-53 interception | A plain DNS query to 192.0.2.1 (TEST-NET-1). Any answer means the network answers DNS for every address. |
| NXDOMAIN hijack | A random name under example.com must not resolve. |
| Transparent HTTP proxy | Proxy headers on a plain-HTTP fetch of example.com. |
| URL keyword filter | Benign words (vpn, proxy, tor, torrent, bypass, unblock) in a query string must be served the same way as a control word. |
| Throttling | 4 MB downloads from 5 CDNs (Cloudflare, Google, Akamai, Microsoft, Fastly). A target below 25 % of the best one on the same link counts as throttled. This is a rough threshold and a busy CDN edge can trip it once, so a repeat run is worth more than a single result. |
| ECH | The site publishes ECH in its HTTPS record. Together with SNI-DPI this means the block can be bypassed with a current browser. |
| IPv6, SSH, vantage point | TCP 443 over IPv6. An SSH banner from github.com. Country and Cloudflare colo from 1.1.1.1. |
| Tor | A real tor bootstrap to 100 %. This needs a tor binary. |

Every positive site result is tested a second time, because a single failed connection is often just a bad moment on the line. A result that does not repeat is marked transient and is not counted.

## The verdict

The analysis gives:

- A score from 0 to 100. The share of affected sites gives up to 50 points. Each technique adds a weight. Each blocked port adds 2 points. Levels: 0 clean, 1 to 19 light, 20 to 44 moderate, 45 to 69 heavy, 70 and above severe.
- The techniques in use, for example SNI-DPI, TLS-MITM, DNS-intercept or throttling.
- A vendor guess when a filter product leaves a signature.
- The affected categories, a confidence rating and one paragraph of text.
- Advice for VPN users and for tunnels. The advice describes what would work on this network. filterscope itself changes nothing.

## Install

Windows: download `filterscope-<version>-Windows-Installer.exe` from the releases page and run it. It creates a Start-menu entry. It does not need administrator rights. SmartScreen shows a warning because the file is not code-signed. Choose "More info" and then "Run anyway". The portable file `filterscope-<version>-Windows-Portable.exe` runs without installation.

Android: install `filterscope-<version>-Android.apk`. Android 7 or newer, 64-bit. Allow "unknown sources" for your browser once.

Linux: download `filterscope-<version>-Linux-App`, run `chmod +x` on it and start it.

macOS with Apple silicon: download `filterscope-<version>-macOS-AppleSilicon.app.zip`, unzip it and open it with a right-click the first time. Intel Macs use the Python install.

Python 3.10 or newer, any OS:

```bash
pipx install git+https://github.com/tunnelmoth/filterscope
```

The `-Terminal` files carry the terminal dashboard and the command line. Every release page starts with a table that says which file you need. Verify each download with `SHA256SUMS.txt` from the same release.

The Tor probe needs a `tor` binary. Install it with apt, pacman or brew. On Windows put `tor.exe` from the Tor Expert Bundle next to the program. An installed Tor Browser is found automatically.

## Use

Desktop window:

```
filterscope gui
```

Press Scan. Read the gauge and the sentence under it. "Open report" renders the HTML report in the browser. "Save" writes HTML, JSON or a PNG share card. "Sites…" selects categories and adds your own domains. "Check…" asks about one service by name.

Terminal dashboard and command line:

```bash
filterscope                                  # terminal dashboard
filterscope scan                             # full scan, exit code 2 when interference is found
filterscope scan --profile quick             # sites and ports plus UDP, QUIC, DNS
filterscope scan --profile school            # the categories a school filter usually touches
filterscope scan --categories ai,vpn-api     # only these categories
filterscope scan --domain example.org        # add your own domains, or --domains-file
filterscope scan --label school --json school.json --html school.html
filterscope scan --anon-json share.json      # report without local identity
filterscope scan --card card.png --lang tr   # PNG share card, Turkish output
filterscope scan --format json               # the report on stdout
filterscope scan --watch 30                  # repeat every 30 min and print the changes
filterscope report school.json               # render a saved report again, or --html
filterscope config set label school          # persistent defaults
```

Terminal dashboard keys: `r` rescan, `t` Tor on or off, `s` save, `/` filter, `f` affected sites only, `c` compare with the previous scan, `d` dark or light, `1` to `5` tabs, `q` quit.

### Ask about one service

```bash
filterscope check valorant
filterscope check discord roblox youtube
filterscope services
filterscope services --template
```

A service profile lists the endpoints the service needs: the website, the login or API servers, the CDN, the game or chat servers. It also lists the TCP ports the service uses. The check measures UDP egress and downloads a file from the service's own CDN, and it compares that download with a Cloudflare baseline. The verdict is OK, PARTIAL, BLOCKED or THROTTLED, with the reasons. The catalogue has 113 profiles, and we expect some of the game endpoints to change over time because vendors move their servers. `services --template` writes `~/.filterscope/services.json`. Edit that file to add your own profiles.

Hosts that do not speak HTTPS on port 443 (for example WhatsApp on 5222, Supercell on 9339, Riot chat on 5223) get a plain TCP connect instead of a TLS probe. UDP game ports cannot be verified without the game. The tool reports generic UDP egress for them.

### Evidence

Run the same scan on two networks and compare the reports:

```bash
filterscope scan --label school --json school.json
filterscope scan --label mobile --json mobile.json
filterscope compare school.json mobile.json
```

Anything blocked on one network and open on the other is probably filtering specific to that network. A site that is down at that moment looks the same, so a second run a few minutes later is a good habit.

Every scan appends one record to `~/.filterscope/history.jsonl` and stores the full report under `~/.filterscope/reports/`.

```bash
filterscope history                          # timeline per network, with new and lifted blocks
filterscope history --html timeline.html
filterscope diff                             # the last two stored scans of this network
```

A cron entry for a time series:

```
*/30 * * * * filterscope scan --no-tor --label school --format summary >> ~/.filterscope/run.log 2>&1
```

### Background mode

```bash
filterscope tray
```

The program sits in the system tray and reads the network fingerprint (gateway, resolver, SSID) every 30 s. When the network changes it runs a quick scan and shows a notification with the blocked sites. The menu offers a scan, one-click service checks and the window. The Windows installer can start this mode at login. The installer can also add "Measure this network with filterscope" to the desktop right-click menu.

### Language, theme, text size

The interface is available in English and Turkish. The language follows the system locale. `--lang tr`, `filterscope config set lang tr` or the EN/TR button in the window override it.

The window follows the OS theme. "View" offers Light, Dark, a high-contrast palette and text sizes from 100 % to 175 %. The terminal dashboard toggles with `d`. The Android app and the HTML report follow the system theme.

### Update check

At start the program makes one request to the GitHub releases API. A newer version shows a bar in the window, a toast in the terminal dashboard, one line in the command line and a tap-to-download bar on Android. `filterscope config set update_check false` turns this off.

### WireGuard test

```bash
filterscope wg --config /etc/wireguard/wg0.conf
```

This sends a real WireGuard handshake (Noise_IKpsk2) to your own server. A response means WireGuard works on this network.

### Cloudflare WARP (Linux only)

```bash
filterscope warp test
filterscope warp up
filterscope warp masque up
filterscope warp status
filterscope warp down
```

This installs Cloudflare WARP without AUR and brings the tunnel up with sudo. Downloads are verified against the release checksums and the apt signature chain. On every other platform use the official 1.1.1.1 app and choose MASQUE in its connection settings.

## How to read the results

- SNI-DPI: the network reads the server name in the TLS ClientHello and resets some sites. "In-path injection" in the note means the reset came from a middlebox.
- TLS-MITM: the network decrypts HTTPS with its own certificate. Every page and every login is readable by the operator.
- HIJACK-blockpage: DNS answers with a private IP.
- DNS-BLOCK: the local resolver returns nothing while DoH resolves.
- INTERCEPTED: the network answers port-53 DNS for every address. A change of resolver to 8.8.8.8 has no effect.
- NXDOMAIN-HIJACK: names that do not exist resolve.
- BLOCKED on DoH or DoT: encrypted DNS is blocked. Firefox DoH and Android Private DNS fail.
- BLOCKED on a port, QUIC or UDP: packets to that port are dropped.
- PROXY or URL-KEYWORD-FILTER: a transparent proxy rewrites plain HTTP.
- THROTTLED: one CDN gets less than 25 % of the speed of the others.

## Android

The app is a Jetpack Compose front-end over the same Python engine (Chaquopy, Python 3.13, arm64-v8a and x86_64). It has the scan, the gauge, the findings, the per-site rows, the egress probes, the history, the service check tab, the share card and "Open report". A home-screen widget shows the last score. A tap on the widget opens the app and starts a scan. The network identity comes from the Android connectivity API. There is no Tor probe on Android.

## Configuration and data

`~/.filterscope/config.json` holds the defaults: `label`, `timeout`, `tor`, `categories`, `domains`, `steps_off`, `workers`, `lang`, `theme`, `high_contrast`, `font_scale`, `update_check`, `verify`, `save_reports`. `filterscope config` prints them. `filterscope config set KEY VALUE` changes one. On Android the same files live in the app's private storage.

## JSON schema

`schema` is 3. Top-level keys: `ts`, `version`, `lang`, `net` (id, label, ssid, gateway, resolver, os), `geo`, `sites`, `ports`, `udp`, `udp_detail`, `quic`, `quic_detail`, `ipv6`, `dns_encrypted`, `dns_intercept`, `nxdomain`, `http_proxy`, `url_filter`, `tls_intercept`, `throttle`, `ssh`, `tor`, `timings`, `flagged`, `analysis`. Each site has `cat`, `dns`, `sni`, `blockpage`, `ech`, `ms` and, after the second test, `confirmed` or `transient`. `analysis` has `score`, `level`, `techniques`, `vendor`, `categories`, `confidence` and `summary`. The anonymized report drops the network identity except id and label, the public IP, the resolver answers and the proxy headers.

## Development

```bash
pip install -e ".[dev]"
pytest
pyinstaller packaging/filterscope.spec        # terminal binary
pyinstaller packaging/filterscope-gui.spec    # windowed binary
cd android && ./gradlew assembleDebug         # Android APK: JDK 17, Android SDK 34, python3.13 on PATH
```

The source layout: `filterscope/core.py` holds the probes, `scan.py` the scheduler, `analysis.py` the score, `services.py` the service profiles, `render.py` the terminal output, `htmlreport.py` the HTML report, `card.py` the share card, `i18n.py` the strings, `gui.py` the window, `tui.py` the dashboard, `tray.py` the background mode and `cli.py` the command line. The landing page is in `docs/`. The Android project is in `android/`.

CI runs the tests on all three desktop platforms. A tag that starts with `v` builds the binaries, the installer and the APK, and it then publishes the release together with `SHA256SUMS.txt`. Actions are pinned to commit hashes.

## Security

See `SECURITY.md`. In short: two TLS handshakes per site run without certificate verification on purpose, because they only observe a reset or read the presented certificate. All other TLS verifies against the Mozilla CA bundle. Binaries are not code-signed. The Android signing key lives in the repository so that sideloaded updates install over each other. It proves nothing about the author.

## Status

Done: the probes above with the analysis and the verification pass. The four front-ends. The service profiles and the share card. The tray mode. A Turkish interface with dark and high-contrast themes. The landing page and the CI release.

Open: a probe that locates the hop where a reset originates (this needs raw sockets), a real ECH handshake, DNS over QUIC and HTTP/3 fetches, a two-network comparison wizard, PDF export and an opt-in aggregate map.

## License

GPL-3.0-or-later.
