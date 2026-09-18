"""Service profiles for `filterscope check <name>`: the endpoints a service really
needs (web, auth/API, CDN, game/voice servers), the ports it uses, and — where the
vendor publishes a large public file on its own CDN — a throughput target.

Only mainstream services; only public, well-known hostnames."""
from __future__ import annotations

# kind: web | api | cdn | game | voice | media | dc.  Optional third field "tcp:PORT" = the host does not
# speak HTTPS on 443 (raw game/chat protocol); only a TCP connect to that port is checked.
SERVICES = {
    "valorant": {
        "name": "Valorant (Riot)", "aliases": ["valo", "vlr"], "category": "games",
        "hosts": [("web", "playvalorant.com"), ("api", "auth.riotgames.com"), ("api", "clientconfig.rpg.riotgames.com"),
                  ("cdn", "riot-client.secure.dyn.riotcdn.net"), ("api", "pd.eu.a.pvp.net"), ("game", "glz-eu-1.eu.a.pvp.net", "tcp:443")],
        "tcp": [443, 8393, 8400, 5223], "udp": [(7000, 8000), (8180, 8181)],
        "download": "ddragon:", "download_note": "Riot static CDN (ddragon)",
    },
    "league": {
        "name": "League of Legends (Riot)", "aliases": ["lol", "leagueoflegends", "riot"], "category": "games",
        "hosts": [("web", "leagueoflegends.com"), ("api", "auth.riotgames.com"), ("api", "clientconfig.rpg.riotgames.com"),
                  ("cdn", "riot-client.secure.dyn.riotcdn.net"), ("cdn", "ddragon.leagueoflegends.com"), ("api", "euw1.chat.si.riotgames.com", "tcp:5223")],
        "tcp": [443, 2099, 5223, 8393, 8400], "udp": [(5000, 5500)],
        "download": "ddragon:",
    },
    "discord": {
        "name": "Discord", "aliases": [], "category": "chat",
        "hosts": [("web", "discord.com"), ("api", "gateway.discord.gg"), ("cdn", "cdn.discordapp.com"), ("media", "media.discordapp.net"),
                  ("api", "status.discord.com"), ("cdn", "dl.discordapp.net")],
        "tcp": [443], "udp": [(50000, 65535)],
        "download": "https://discord.com/api/download?platform=win",
    },
    "roblox": {
        "name": "Roblox", "aliases": ["rblx"], "category": "games",
        "hosts": [("web", "roblox.com"), ("web", "www.roblox.com"), ("api", "apis.roblox.com"), ("api", "auth.roblox.com"),
                  ("cdn", "setup.rbxcdn.com"), ("cdn", "tr.rbxcdn.com")],
        "tcp": [443], "udp": [(49152, 65535)],
        "download": "https://setup.rbxcdn.com/RobloxPlayerLauncher.exe",
    },
    "minecraft": {
        "name": "Minecraft", "aliases": ["mc", "mojang"], "category": "games",
        "hosts": [("web", "minecraft.net"), ("api", "api.minecraftservices.com"), ("api", "sessionserver.mojang.com"),
                  ("cdn", "piston-meta.mojang.com"), ("cdn", "piston-data.mojang.com"), ("cdn", "resources.download.minecraft.net"),
                  ("cdn", "launcher.mojang.com")],
        "tcp": [443, 25565], "udp": [],
        "download": "https://launcher.mojang.com/download/Minecraft.exe",
    },
    "fortnite": {
        "name": "Fortnite / Epic Games", "aliases": ["epic", "epicgames"], "category": "games",
        "hosts": [("web", "epicgames.com"), ("web", "fortnite.com"), ("api", "account-public-service-prod.ol.epicgames.com"),
                  ("api", "launcher-public-service-prod06.ol.epicgames.com"), ("cdn", "epicgames-download1.akamaized.net"),
                  ("api", "fortnite-public-service-prod11.ol.epicgames.com")],
        "tcp": [443, 5222], "udp": [(5795, 5847), (9000, 9100)],
        "download": "https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/installer/download/EpicGamesLauncherInstaller.msi",
    },
    "steam": {
        "name": "Steam", "aliases": ["cs2", "csgo", "dota"], "category": "games",
        "hosts": [("web", "store.steampowered.com"), ("api", "api.steampowered.com"), ("web", "steamcommunity.com"),
                  ("cdn", "cdn.akamai.steamstatic.com"), ("cdn", "cdn.cloudflare.steamstatic.com"), ("api", "steamcdn-a.akamaihd.net")],
        "tcp": [443, 27015, 27036], "udp": [(27000, 27100), (3478, 3478), (4379, 4380)],
        "download": "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe",
    },
    "genshin": {
        "name": "Genshin Impact (HoYoverse)", "aliases": ["hoyoverse", "mihoyo", "honkai"], "category": "games",
        "hosts": [("web", "hoyoverse.com"), ("web", "genshin.hoyoverse.com"), ("api", "sdk-os-static.hoyoverse.com"),
                  ("cdn", "autopatchhk.yuanshen.com"), ("api", "sg-hk4e-api.hoyoverse.com")],
        "tcp": [443], "udp": [(22101, 22102)],
        "download": "",
    },
    "supercell": {
        "name": "Brawl Stars / Clash (Supercell)", "aliases": ["brawl", "brawlstars", "clash", "clashofclans", "clashroyale"], "category": "games",
        "hosts": [("web", "supercell.com"), ("game", "game.brawlstarsgame.com", "tcp:9339"), ("game", "gamea.clashofclans.com", "tcp:9339"),
                  ("game", "game.clashroyaleapp.com", "tcp:9339"), ("api", "id.supercell.com")],
        "tcp": [443, 9339], "udp": [],
        "download": "",
    },
    "pubg": {
        "name": "PUBG", "aliases": ["pubgmobile"], "category": "games",
        "hosts": [("web", "pubg.com"), ("api", "accounts.krafton.com"), ("web", "pubgmobile.com"), ("api", "prod-live-front.playbattlegrounds.com")],
        "tcp": [443], "udp": [(7000, 7999), (20000, 20100)],
        "download": "",
    },
    "youtube": {
        "name": "YouTube", "aliases": ["yt"], "category": "video",
        "hosts": [("web", "youtube.com"), ("web", "www.youtube.com"), ("cdn", "i.ytimg.com"), ("media", "redirector.googlevideo.com"),
                  ("media", "rr1---sn-4g5e6nzs.googlevideo.com", "tcp:443"), ("api", "youtubei.googleapis.com"), ("cdn", "yt3.ggpht.com")],
        "tcp": [443], "udp": [(443, 443)],
        "download": "https://dl.google.com/chrome/install/latest/chrome_installer.exe",
        "download_note": "Google CDN (googlevideo needs a signed URL)",
    },
    "twitch": {
        "name": "Twitch", "aliases": [], "category": "video",
        "hosts": [("web", "twitch.tv"), ("web", "www.twitch.tv"), ("api", "gql.twitch.tv"), ("api", "usher.ttvnw.net"),
                  ("cdn", "static-cdn.jtvnw.net"), ("media", "video-weaver.fra02.hls.ttvnw.net", "tcp:443")],
        "tcp": [443], "udp": [],
        "download": "",
    },
    "kick": {
        "name": "Kick", "aliases": [], "category": "video",
        "hosts": [("web", "kick.com"), ("api", "kick.com"), ("media", "stream.kick.com"), ("cdn", "files.kick.com")],
        "tcp": [443], "udp": [], "download": "",
    },
    "netflix": {
        "name": "Netflix", "aliases": [], "category": "video",
        "hosts": [("web", "netflix.com"), ("web", "www.netflix.com"), ("api", "api-global.netflix.com"), ("api", "ichnaea.netflix.com"),
                  ("cdn", "assets.nflxext.com"), ("web", "fast.com")],
        "tcp": [443], "udp": [],
        "download": "fast.com",
    },
    "spotify": {
        "name": "Spotify", "aliases": [], "category": "music",
        "hosts": [("web", "spotify.com"), ("web", "open.spotify.com"), ("api", "api.spotify.com"), ("api", "accounts.spotify.com"),
                  ("media", "audio-fa.scdn.co"), ("cdn", "i.scdn.co")],
        "tcp": [443, 4070], "udp": [],
        "download": "https://download.scdn.co/SpotifySetup.exe",
    },
    "whatsapp": {
        "name": "WhatsApp", "aliases": ["wa"], "category": "chat",
        "hosts": [("web", "whatsapp.com"), ("web", "web.whatsapp.com"), ("api", "g.whatsapp.net", "tcp:5222"), ("media", "mmg.whatsapp.net"),
                  ("api", "static.whatsapp.net"), ("voice", "v.whatsapp.net", "tcp:443")],
        "tcp": [443, 5222], "udp": [(3478, 3478), (45395, 45395)],
        "download": "",
    },
    "telegram": {
        "name": "Telegram", "aliases": ["tg"], "category": "messaging",
        "hosts": [("web", "telegram.org"), ("web", "web.telegram.org"), ("api", "api.telegram.org"), ("api", "core.telegram.org"),
                  ("cdn", "cdn4.telesco.pe"), ("dc", "149.154.167.50"), ("dc", "149.154.175.50"), ("dc", "91.108.4.150")],
        "tcp": [443, 80], "udp": [],
        "download": "https://telegram.org/dl/desktop/win64",
    },
    "signal": {
        "name": "Signal", "aliases": [], "category": "messaging",
        "hosts": [("web", "signal.org"), ("api", "chat.signal.org"), ("api", "storage.signal.org"), ("cdn", "cdn.signal.org"),
                  ("cdn", "cdn2.signal.org"), ("api", "sfu.voip.signal.org"), ("cdn", "updates.signal.org")],
        "tcp": [443], "udp": [(10000, 10000)],
        "download": "",
    },
    "zoom": {
        "name": "Zoom", "aliases": [], "category": "chat",
        "hosts": [("web", "zoom.us"), ("api", "api.zoom.us"), ("web", "app.zoom.us"), ("cdn", "cdn.zoom.us")],
        "tcp": [443, 8801, 8802], "udp": [(8801, 8810), (3478, 3479)],
        "download": "https://zoom.us/client/latest/ZoomInstallerFull.exe",
    },
    "teams": {
        "name": "Microsoft Teams", "aliases": ["msteams"], "category": "chat",
        "hosts": [("web", "teams.microsoft.com"), ("web", "teams.live.com"), ("api", "login.microsoftonline.com"),
                  ("cdn", "statics.teams.cdn.office.net"), ("api", "presence.teams.microsoft.com")],
        "tcp": [443], "udp": [(3478, 3481)],
        "download": "https://aka.ms/vs/17/release/vc_redist.x64.exe", "download_note": "Microsoft CDN",
    },
    "instagram": {
        "name": "Instagram", "aliases": ["ig", "insta"], "category": "social",
        "hosts": [("web", "instagram.com"), ("web", "www.instagram.com"), ("api", "i.instagram.com"), ("api", "graph.instagram.com"),
                  ("cdn", "static.cdninstagram.com"), ("media", "scontent.cdninstagram.com")],
        "tcp": [443], "udp": [], "download": "",
    },
    "tiktok": {
        "name": "TikTok", "aliases": [], "category": "video",
        "hosts": [("web", "tiktok.com"), ("web", "www.tiktok.com"), ("api", "api16-normal-c-useast1a.tiktokv.com"),
                  ("media", "v16-webapp-prime.tiktok.com"), ("cdn", "sf16-website-login.neutral.ttwstatic.com"), ("api", "webcast.tiktok.com")],
        "tcp": [443], "udp": [(443, 443)], "download": "",
    },
    "x": {
        "name": "X (Twitter)", "aliases": ["twitter"], "category": "social",
        "hosts": [("web", "x.com"), ("web", "twitter.com"), ("api", "api.x.com"), ("cdn", "abs.twimg.com"), ("media", "pbs.twimg.com"),
                  ("media", "video.twimg.com")],
        "tcp": [443], "udp": [], "download": "",
    },
    "chatgpt": {
        "name": "ChatGPT / OpenAI", "aliases": ["openai", "gpt"], "category": "ai",
        "hosts": [("web", "chatgpt.com"), ("api", "api.openai.com"), ("api", "auth.openai.com"), ("cdn", "cdn.oaistatic.com"),
                  ("api", "ab.chatgpt.com")],
        "tcp": [443], "udp": [], "download": "",
    },
    "claude": {
        "name": "Claude / Anthropic", "aliases": ["anthropic"], "category": "ai",
        "hosts": [("web", "claude.ai"), ("api", "api.anthropic.com"), ("web", "anthropic.com"), ("web", "console.anthropic.com")],
        "tcp": [443], "udp": [], "download": "",
    },
    "gemini": {
        "name": "Gemini (Google)", "aliases": ["bard"], "category": "ai",
        "hosts": [("web", "gemini.google.com"), ("api", "generativelanguage.googleapis.com"), ("web", "aistudio.google.com"),
                  ("api", "accounts.google.com")],
        "tcp": [443], "udp": [(443, 443)], "download": "",
    },
    "protonvpn": {
        "name": "Proton VPN", "aliases": ["proton"], "category": "vpn",
        "hosts": [("web", "protonvpn.com"), ("api", "api.protonvpn.ch"), ("api", "account.proton.me"), ("web", "proton.me"),
                  ("api", "vpn-api.proton.me")],
        "tcp": [443, 1194, 5995], "udp": [(51820, 51820), (1194, 1194), (443, 443)], "download": "",
    },
    "wireguard": {
        "name": "WireGuard (generic)", "aliases": ["wg"], "category": "vpn",
        "hosts": [("web", "wireguard.com")], "tcp": [], "udp": [(51820, 51820)], "download": "",
    },
    "github": {
        "name": "GitHub", "aliases": ["gh"], "category": "dev",
        "hosts": [("web", "github.com"), ("api", "api.github.com"), ("cdn", "objects.githubusercontent.com"), ("cdn", "raw.githubusercontent.com"),
                  ("cdn", "github.githubassets.com"), ("web", "codeload.github.com")],
        "tcp": [443, 22], "udp": [],
        "download": "https://codeload.github.com/torvalds/linux/tar.gz/refs/tags/v6.1",
    },
    "wikipedia": {
        "name": "Wikipedia", "aliases": ["wiki"], "category": "info",
        "hosts": [("web", "wikipedia.org"), ("web", "en.wikipedia.org"), ("web", "tr.wikipedia.org"), ("cdn", "upload.wikimedia.org")],
        "tcp": [443], "udp": [],
        "download": "https://upload.wikimedia.org/wikipedia/commons/3/3f/Fronalpstock_big.jpg",
    },
}


def find(query: str):
    """Resolve a user query to a service key (exact key, alias, or unique substring)."""
    q = (query or "").strip().lower().replace(" ", "")
    if not q:
        return None
    if q in SERVICES:
        return q
    for k, s in SERVICES.items():
        if q in [a.lower() for a in s.get("aliases", [])] or q == s["name"].lower().replace(" ", ""):
            return k
    hits = [k for k, s in SERVICES.items() if q in k or q in s["name"].lower().replace(" ", "") or any(q in a for a in s.get("aliases", []))]
    return hits[0] if len(hits) == 1 else None


def suggestions(query: str, limit=6):
    q = (query or "").strip().lower()
    out = []
    for k, s in SERVICES.items():
        hay = " ".join([k, s["name"].lower()] + s.get("aliases", []))
        if not q or q in hay:
            out.append((k, s["name"]))
    return out[:limit]
