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
    # ── more games ──
    "cs2": {"name": "Counter-Strike 2 (Steam)", "aliases": ["csgo", "counterstrike"], "category": "games",
            "hosts": [("web", "counter-strike.net"), ("api", "api.steampowered.com"), ("web", "steamcommunity.com"), ("cdn", "cdn.akamai.steamstatic.com"),],
            "tcp": [443, 27015, 27017, 27036], "udp": [(27015, 27030), (3478, 3478)], "download": "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe"},
    "dota2": {"name": "Dota 2 (Steam)", "aliases": ["dota"], "category": "games",
              "hosts": [("web", "dota2.com"), ("api", "api.steampowered.com"), ("cdn", "cdn.akamai.steamstatic.com"),],
              "tcp": [443, 27015, 27017], "udp": [(27015, 27030)], "download": "https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe"},
    "apex": {"name": "Apex Legends (EA)", "aliases": ["apexlegends", "ea", "origin"], "category": "games",
             "hosts": [("web", "ea.com"), ("api", "accounts.ea.com"), ("api", "api1.origin.com"), ("cdn", "origin-a.akamaihd.net"),],
             "tcp": [443, 9960, 9988], "udp": [(1024, 1124), (18000, 18100), (37000, 40000)], "download": ""},
    "fifa": {"name": "EA FC / FIFA (EA)", "aliases": ["eafc", "fc25", "fc24"], "category": "games",
             "hosts": [("web", "ea.com"), ("api", "accounts.ea.com"), ("api", "gateway.ea.com"), ("cdn", "origin-a.akamaihd.net")],
             "tcp": [443, 9960], "udp": [(3659, 3659), (9000, 9999)], "download": ""},
    "rainbowsix": {"name": "Rainbow Six Siege (Ubisoft)", "aliases": ["r6", "siege", "ubisoft", "uplay"], "category": "games",
                   "hosts": [("web", "ubisoft.com"), ("api", "public-ubiservices.ubi.com"), ("api", "connect.ubisoft.com"), ("cdn", "static3.cdn.ubi.com"), ("cdn", "ubistatic-a.akamaihd.net")],
                   "tcp": [443, 13000, 13005, 13200, 14000], "udp": [(6015, 6015), (10000, 10099), (3074, 3074)], "download": ""},
    "overwatch": {"name": "Overwatch 2 (Blizzard)", "aliases": ["ow2", "blizzard", "battlenet", "wow", "hearthstone", "diablo"], "category": "games",
                  "hosts": [("web", "blizzard.com"), ("web", "battle.net"), ("api", "eu.battle.net"), ("api", "us.battle.net"), ("cdn", "blzddist1-a.akamaihd.net"), ("api", "eu.actual.battle.net", "tcp:1119")],
                  "tcp": [443, 1119, 6881, 3724], "udp": [(1119, 1119), (5060, 5062), (27000, 27100)], "download": ""},
    "xboxlive": {"name": "Xbox Live / Xbox app", "aliases": ["xbox", "gamepass"], "category": "games",
                 "hosts": [("web", "xbox.com"), ("api", "xboxlive.com"), ("api", "login.live.com"), ("api", "xsts.auth.xboxlive.com"), ("api", "presence-heartbeat.xboxlive.com"), ("cdn", "assets1.xboxlive.com")],
                 "tcp": [443, 3074], "udp": [(3074, 3074), (88, 88), (500, 500), (3544, 3544), (4500, 4500)], "download": ""},
    "playstation": {"name": "PlayStation Network", "aliases": ["psn", "ps5", "ps4"], "category": "games",
                    "hosts": [("web", "playstation.com"), ("api", "auth.api.sonyentertainmentnetwork.com"), ("api", "ca.account.sony.com"), ("api", "web.np.playstation.com"), ("cdn", "gs2.ww.prod.dl.playstation.net")],
                    "tcp": [443, 3478, 3479, 3480], "udp": [(3478, 3479), (49152, 65535)], "download": ""},
    "nintendo": {"name": "Nintendo Switch Online", "aliases": ["switch", "nso"], "category": "games",
                 "hosts": [("web", "nintendo.com"), ("api", "accounts.nintendo.com"), ("api", "api.accounts.nintendo.com"), ("api", "ctest.cdn.nintendo.net"), ("cdn", "atum.hac.lp1.d4c.nintendo.net")],
                 "tcp": [443], "udp": [(1024, 1124), (45000, 65535)], "download": ""},
    "gta": {"name": "GTA Online / Rockstar", "aliases": ["rockstar", "gtaonline", "rdr2"], "category": "games",
            "hosts": [("web", "rockstargames.com"), ("api", "socialclub.rockstargames.com"), ("api", "prod.ros.rockstargames.com"), ("cdn", "gamedownloads.rockstargames.com"), ("api", "rgl-prod.ros.rockstargames.com")],
            "tcp": [443, 6672], "udp": [(6672, 6672), (61455, 61458)], "download": ""},
    "amongus": {"name": "Among Us", "aliases": [], "category": "games",
                "hosts": [("web", "innersloth.com"), ("game", "matchmaker.among.us", "tcp:443"), ("game", "matchmaker-eu.among.us", "tcp:443"), ("api", "backend.innersloth.com")],
                "tcp": [443, 22023], "udp": [(22023, 22023), (22123, 22123)], "download": ""},
    "freefire": {"name": "Free Fire (Garena)", "aliases": ["garena", "ff"], "category": "games",
                 "hosts": [("web", "garena.com"), ("web", "ff.garena.com"), ("api", "auth.garena.com"), ("cdn", "dl.dir.freefiremobile.com"), ("api", "100067.connect.garena.com")],
                 "tcp": [443, 10000, 10001], "udp": [(10000, 10012), (39698, 39699)], "download": ""},
    "codm": {"name": "Call of Duty (Activision)", "aliases": ["cod", "warzone", "callofduty", "activision"], "category": "games",
             "hosts": [("web", "callofduty.com"), ("api", "profile.callofduty.com"), ("api", "activision.com"), ("api", "s.activision.com"), ("cdn", "blzddist1-a.akamaihd.net")],
             "tcp": [443, 3074, 3075, 27014], "udp": [(3074, 3079), (30000, 45000)], "download": ""},
    "mobilelegends": {"name": "Mobile Legends (Moonton)", "aliases": ["mlbb", "moonton"], "category": "games",
                      "hosts": [("web", "mobilelegends.com"), ("api", "api.mobilelegends.com"), ("cdn", "img.mobilelegends.com")],
                      "tcp": [443, 5000, 5001], "udp": [(5000, 5015), (30000, 30200)], "download": ""},
    "eafc_mobile": {"name": "EA Sports FC Mobile", "aliases": ["fcmobile", "fifamobile"], "category": "games",
                    "hosts": [("web", "ea.com"), ("api", "accounts.ea.com"), ("cdn", "origin-a.akamaihd.net")],
                    "tcp": [443], "udp": [], "download": ""},
    "unity": {"name": "Unity Gaming Services", "aliases": ["unityads"], "category": "games",
              "hosts": [("web", "unity.com"), ("api", "services.api.unity.com"), ("api", "cdp.cloud.unity3d.com"), ("api", "config.unityads.unity3d.com"), ("cdn", "download.unity3d.com")],
              "tcp": [443], "udp": [], "download": ""},
    "geforcenow": {"name": "GeForce NOW (NVIDIA)", "aliases": ["gfn", "nvidia"], "category": "games",
                   "hosts": [("web", "nvidia.com"), ("web", "play.geforcenow.com"), ("api", "login.nvgs.nvidia.com"), ("api", "pcs.geforcenow.com"), ("cdn", "gfn.nvidia.com")],
                   "tcp": [443, 49006], "udp": [(49003, 49006), (5001, 5001)], "download": ""},
    "chess": {"name": "Chess.com / Lichess", "aliases": ["lichess", "chesscom"], "category": "games",
              "hosts": [("web", "chess.com"), ("api", "api.chess.com"), ("web", "lichess.org"), ("api", "socket.lichess.org"), ("cdn", "images.chesscomfiles.com")],
              "tcp": [443], "udp": [], "download": ""},
    "itch": {"name": "itch.io / GOG", "aliases": ["gog"], "category": "games",
             "hosts": [("web", "itch.io"), ("api", "api.itch.io"), ("cdn", "img.itch.zone"), ("web", "gog.com"), ("api", "api.gog.com"), ("cdn", "gog-cdn-fastly.gog.com")],
             "tcp": [443], "udp": [], "download": ""},
    # ── more video / music ──
    "primevideo": {"name": "Prime Video (Amazon)", "aliases": ["amazonprime", "prime"], "category": "video",
                   "hosts": [("web", "primevideo.com"), ("web", "amazon.com"), ("api", "atv-ps.amazon.com"), ("cdn", "m.media-amazon.com"), ("api", "api.amazon.com")],
                   "tcp": [443], "udp": [], "download": ""},
    "disneyplus": {"name": "Disney+", "aliases": ["disney"], "category": "video",
                   "hosts": [("web", "disneyplus.com"), ("api", "disney.api.edge.bamgrid.com"), ("cdn", "cdn.registerdisney.go.com"), ("api", "global.edge.bamgrid.com")],
                   "tcp": [443], "udp": [], "download": ""},
    "max": {"name": "Max (HBO)", "aliases": ["hbo", "hbomax"], "category": "video",
            "hosts": [("web", "max.com"), ("api", "default.any-any.prd.api.discomax.com"), ("cdn", "beam-images.warnermediacdn.com"), ("web", "hbomax.com")],
            "tcp": [443], "udp": [], "download": ""},
    "crunchyroll": {"name": "Crunchyroll", "aliases": ["anime"], "category": "video",
                    "hosts": [("web", "crunchyroll.com"), ("api", "beta-api.crunchyroll.com"), ("cdn", "static.crunchyroll.com"),],
                    "tcp": [443], "udp": [], "download": ""},
    "exxen": {"name": "Exxen", "aliases": [], "category": "video",
              "hosts": [("web", "exxen.com"),],
              "tcp": [443], "udp": [], "download": ""},
    "blutv": {"name": "BluTV", "aliases": [], "category": "video",
              "hosts": [("web", "blutv.com"), ("api", "api.blutv.com"), ("cdn", "static.blutv.com"),],
              "tcp": [443], "udp": [], "download": ""},
    "applemusic": {"name": "Apple Music / iTunes", "aliases": ["itunes", "appletv"], "category": "music",
                   "hosts": [("web", "music.apple.com"), ("api", "amp-api.music.apple.com"), ("cdn", "is1-ssl.mzstatic.com"), ("media", "audio-ssl.itunes.apple.com"), ("api", "buy.itunes.apple.com")],
                   "tcp": [443], "udp": [], "download": ""},
    "soundcloud": {"name": "SoundCloud", "aliases": [], "category": "music",
                   "hosts": [("web", "soundcloud.com"), ("api", "api-v2.soundcloud.com"), ("media", "cf-hls-media.sndcdn.com"), ("cdn", "i1.sndcdn.com")],
                   "tcp": [443], "udp": [], "download": ""},
    "deezer": {"name": "Deezer", "aliases": [], "category": "music",
               "hosts": [("web", "deezer.com"), ("api", "api.deezer.com"), ("cdn", "e-cdns-images.dzcdn.net"),],
               "tcp": [443], "udp": [], "download": ""},
    "dailymotion": {"name": "Dailymotion / Vimeo", "aliases": ["vimeo"], "category": "video",
                    "hosts": [("web", "dailymotion.com"), ("api", "api.dailymotion.com"), ("web", "vimeo.com"), ("api", "api.vimeo.com"), ("cdn", "i.vimeocdn.com")],
                    "tcp": [443], "udp": [], "download": ""},
    # ── more social / chat ──
    "facebook": {"name": "Facebook / Messenger", "aliases": ["fb", "messenger", "meta"], "category": "social",
                 "hosts": [("web", "facebook.com"), ("web", "www.facebook.com"), ("api", "graph.facebook.com"), ("web", "messenger.com"), ("api", "edge-chat.facebook.com"), ("cdn", "static.xx.fbcdn.net"), ("media", "scontent.xx.fbcdn.net")],
                 "tcp": [443, 5222], "udp": [(3478, 3478), (40000, 40100)], "download": ""},
    "threads": {"name": "Threads", "aliases": [], "category": "social",
                "hosts": [("web", "threads.net"), ("web", "www.threads.net"), ("api", "i.instagram.com"), ("cdn", "static.cdninstagram.com")],
                "tcp": [443], "udp": [], "download": ""},
    "snapchat": {"name": "Snapchat", "aliases": ["snap"], "category": "social",
                 "hosts": [("web", "snapchat.com"), ("api", "app.snapchat.com"), ("api", "auth.snapchat.com"), ("cdn", "cf-st.sc-cdn.net"), ("media", "bolt-gcdn.sc-cdn.net")],
                 "tcp": [443], "udp": [], "download": ""},
    "reddit": {"name": "Reddit", "aliases": [], "category": "social",
               "hosts": [("web", "reddit.com"), ("web", "www.reddit.com"), ("api", "oauth.reddit.com"), ("api", "gql.reddit.com"), ("cdn", "www.redditstatic.com"), ("media", "i.redd.it"), ("media", "v.redd.it")],
               "tcp": [443], "udp": [], "download": ""},
    "pinterest": {"name": "Pinterest", "aliases": [], "category": "social",
                  "hosts": [("web", "pinterest.com"), ("web", "www.pinterest.com"), ("api", "api.pinterest.com"), ("cdn", "i.pinimg.com"), ("cdn", "s.pinimg.com")],
                  "tcp": [443], "udp": [], "download": ""},
    "linkedin": {"name": "LinkedIn", "aliases": [], "category": "social",
                 "hosts": [("web", "linkedin.com"), ("web", "www.linkedin.com"), ("api", "api.linkedin.com"), ("cdn", "static.licdn.com"), ("media", "media.licdn.com")],
                 "tcp": [443], "udp": [], "download": ""},
    "tumblr": {"name": "Tumblr / DeviantArt", "aliases": ["deviantart"], "category": "social",
               "hosts": [("web", "tumblr.com"), ("api", "api.tumblr.com"), ("cdn", "64.media.tumblr.com"), ("web", "deviantart.com"), ("cdn", "images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com")],
               "tcp": [443], "udp": [], "download": ""},
    "vk": {"name": "VK", "aliases": ["vkontakte"], "category": "social",
           "hosts": [("web", "vk.com"), ("api", "api.vk.com"), ("api", "login.vk.com"), ("cdn", "st.vk.com"), ("media", "sun9-1.userapi.com")],
           "tcp": [443], "udp": [], "download": ""},
    "wechat": {"name": "WeChat", "aliases": ["weixin"], "category": "chat",
               "hosts": [("web", "wechat.com"), ("api", "web.wechat.com"), ("api", "long.weixin.qq.com", "tcp:443"), ("api", "short.weixin.qq.com"), ("cdn", "res.wx.qq.com")],
               "tcp": [443, 80, 8080], "udp": [], "download": ""},
    "viber": {"name": "Viber", "aliases": [], "category": "messaging",
              "hosts": [("web", "viber.com"), ("api", "content.cdn.viber.com"), ("cdn", "download.cdn.viber.com")],
              "tcp": [443, 5242, 4244], "udp": [(5243, 5243), (9785, 9785)], "download": ""},
    "skype": {"name": "Skype", "aliases": [], "category": "chat",
              "hosts": [("web", "skype.com"), ("web", "web.skype.com"), ("api", "api.skype.com"), ("api", "login.skype.com"), ("cdn", "secure.skypeassets.com")],
              "tcp": [443, 3478, 3479], "udp": [(3478, 3481), (50000, 50059)], "download": ""},
    "slack": {"name": "Slack", "aliases": [], "category": "chat",
              "hosts": [("web", "slack.com"), ("web", "app.slack.com"), ("api", "wss-primary.slack.com"), ("api", "edgeapi.slack.com"), ("cdn", "a.slack-edge.com"), ("media", "files.slack.com")],
              "tcp": [443], "udp": [(3478, 3478), (22466, 22466)], "download": ""},
    "googlemeet": {"name": "Google Meet", "aliases": ["meet", "hangouts"], "category": "chat",
                   "hosts": [("web", "meet.google.com"), ("api", "accounts.google.com"), ("api", "lens.l.google.com", "tcp:443"), ("api", "meetings.googleapis.com"), ("cdn", "www.gstatic.com")],
                   "tcp": [443], "udp": [(19302, 19309), (3478, 3478)], "download": ""},
    "element": {"name": "Element / Matrix", "aliases": ["matrix"], "category": "messaging",
                "hosts": [("web", "element.io"), ("web", "app.element.io"), ("api", "matrix.org"), ("api", "matrix-client.matrix.org"), ("cdn", "static.element.io")],
                "tcp": [443, 8448], "udp": [(3478, 3478)], "download": ""},
    # ── more AI ──
    "copilot": {"name": "Microsoft Copilot / Bing AI", "aliases": ["bing"], "category": "ai",
                "hosts": [("web", "copilot.microsoft.com"), ("web", "bing.com"), ("api", "sydney.bing.com"), ("api", "login.live.com"), ("cdn", "r.bing.com")],
                "tcp": [443], "udp": [], "download": ""},
    "perplexity": {"name": "Perplexity", "aliases": [], "category": "ai",
                   "hosts": [("web", "perplexity.ai"), ("web", "www.perplexity.ai"), ("api", "api.perplexity.ai"), ("cdn", "pplx-res.cloudinary.com")],
                   "tcp": [443], "udp": [], "download": ""},
    "deepseek": {"name": "DeepSeek", "aliases": [], "category": "ai",
                 "hosts": [("web", "deepseek.com"), ("web", "chat.deepseek.com"), ("api", "api.deepseek.com"), ("cdn", "cdn.deepseek.com")],
                 "tcp": [443], "udp": [], "download": ""},
    "huggingface": {"name": "Hugging Face", "aliases": ["hf"], "category": "ai",
                    "hosts": [("web", "huggingface.co"),],
                    "tcp": [443], "udp": [], "download": ""},
    "mistral": {"name": "Mistral AI", "aliases": ["lechat"], "category": "ai",
                "hosts": [("web", "mistral.ai"), ("web", "chat.mistral.ai"), ("api", "api.mistral.ai"), ("api", "console.mistral.ai")],
                "tcp": [443], "udp": [], "download": ""},
    "grok": {"name": "Grok (xAI)", "aliases": ["xai"], "category": "ai",
             "hosts": [("web", "grok.com"), ("web", "x.ai"), ("api", "api.x.ai"), ("cdn", "assets.grok.com")],
             "tcp": [443], "udp": [], "download": ""},
    "characterai": {"name": "Character.AI", "aliases": ["cai"], "category": "ai",
                    "hosts": [("web", "character.ai"), ("api", "beta.character.ai"), ("api", "neo.character.ai"), ("cdn", "characterai.io")],
                    "tcp": [443], "udp": [], "download": ""},
    # ── more VPN / privacy ──
    "mullvad": {"name": "Mullvad VPN", "aliases": [], "category": "vpn",
                "hosts": [("web", "mullvad.net"), ("api", "api.mullvad.net"), ("web", "am.i.mullvad.net"), ("api", "ipv4.am.i.mullvad.net")],
                "tcp": [443, 1401, 53], "udp": [(51820, 51820), (1194, 1194), (53, 53)], "download": ""},
    "nordvpn": {"name": "NordVPN", "aliases": ["nord"], "category": "vpn",
                "hosts": [("web", "nordvpn.com"), ("api", "api.nordvpn.com"), ("api", "zwyr157wwiu6eior.com"), ("cdn", "downloads.nordcdn.com")],
                "tcp": [443, 1194], "udp": [(51820, 51820), (1194, 1194)], "download": ""},
    "expressvpn": {"name": "ExpressVPN", "aliases": ["express"], "category": "vpn",
                   "hosts": [("web", "expressvpn.com"), ("web", "www.expressvpn.com"),],
                   "tcp": [443, 1194, 8080], "udp": [(1195, 1195), (1194, 1194)], "download": ""},
    "surfshark": {"name": "Surfshark", "aliases": [], "category": "vpn",
                  "hosts": [("web", "surfshark.com"), ("api", "api.surfshark.com"), ("cdn", "downloads.surfshark.com")],
                  "tcp": [443, 1443], "udp": [(51820, 51820), (1194, 1194)], "download": ""},
    "windscribe": {"name": "Windscribe", "aliases": [], "category": "vpn",
                   "hosts": [("web", "windscribe.com"), ("api", "api.windscribe.com"), ("api", "assets.windscribe.com")],
                   "tcp": [443, 1194, 80], "udp": [(443, 443), (1194, 1194), (53, 53)], "download": ""},
    "tor": {"name": "Tor Project", "aliases": ["torbrowser", "onion"], "category": "privacy",
            "hosts": [("web", "torproject.org"), ("web", "www.torproject.org"), ("api", "bridges.torproject.org"), ("api", "snowflake.torproject.org"), ("cdn", "dist.torproject.org"), ("api", "check.torproject.org")],
            "tcp": [443, 9001, 9030], "udp": [(3478, 3478)], "download": ""},
    "tailscale": {"name": "Tailscale", "aliases": [], "category": "vpn",
                  "hosts": [("web", "tailscale.com"), ("api", "login.tailscale.com"), ("api", "controlplane.tailscale.com"), ("api", "derp1.tailscale.com"), ("cdn", "pkgs.tailscale.com")],
                  "tcp": [443], "udp": [(41641, 41641), (3478, 3478)], "download": ""},
    "cloudflarewarp": {"name": "Cloudflare WARP / 1.1.1.1", "aliases": ["1111", "cloudflare"], "category": "vpn",
                       "hosts": [("web", "one.one.one.one"), ("api", "api.cloudflareclient.com"), ("api", "engage.cloudflareclient.com"), ("cdn", "pkg.cloudflareclient.com"), ("dc", "162.159.192.1")],
                       "tcp": [443, 853], "udp": [(2408, 2408), (500, 500), (4500, 4500), (1701, 1701)], "download": "https://speed.cloudflare.com/__down?bytes=4000000"},
    # ── productivity / cloud / mail ──
    "gmail": {"name": "Gmail / Google Workspace", "aliases": ["google", "gdrive", "drive", "gsuite"], "category": "mail",
              "hosts": [("web", "mail.google.com"), ("api", "accounts.google.com"), ("web", "drive.google.com"), ("api", "www.googleapis.com"), ("cdn", "ssl.gstatic.com"), ("api", "smtp.gmail.com", "tcp:465"), ("api", "imap.gmail.com", "tcp:993")],
              "tcp": [443, 465, 587, 993], "udp": [(443, 443)], "download": "https://dl.google.com/chrome/install/latest/chrome_installer.exe"},
    "outlook": {"name": "Outlook / Microsoft 365", "aliases": ["office", "office365", "m365", "onedrive"], "category": "mail",
                "hosts": [("web", "outlook.live.com"), ("web", "outlook.office.com"), ("api", "login.microsoftonline.com"), ("web", "onedrive.live.com"), ("api", "graph.microsoft.com"), ("api", "outlook.office365.com", "tcp:993"), ("api", "smtp.office365.com", "tcp:587")],
                "tcp": [443, 587, 993], "udp": [], "download": "https://aka.ms/vs/17/release/vc_redist.x64.exe", "download_note": "Microsoft CDN"},
    "icloud": {"name": "iCloud / Apple ID", "aliases": ["apple", "appleid", "imessage", "facetime"], "category": "storage",
               "hosts": [("web", "icloud.com"), ("api", "appleid.apple.com"), ("api", "gsa.apple.com"), ("api", "setup.icloud.com"), ("api", "courier.push.apple.com", "tcp:5223"), ("cdn", "updates.cdn-apple.com"), ("api", "init.ess.apple.com")],
               "tcp": [443, 5223, 2197], "udp": [(3478, 3497), (16384, 16387)], "download": ""},
    "yandex": {"name": "Yandex", "aliases": ["yandexmail", "yandexdisk"], "category": "mail",
               "hosts": [("web", "yandex.com"), ("web", "mail.yandex.com"), ("api", "passport.yandex.com"), ("web", "disk.yandex.com"), ("cdn", "yastatic.net")],
               "tcp": [443, 993, 465], "udp": [], "download": ""},
    "dropbox": {"name": "Dropbox", "aliases": [], "category": "storage",
                "hosts": [("web", "dropbox.com"), ("web", "www.dropbox.com"), ("api", "api.dropboxapi.com"), ("api", "content.dropboxapi.com"), ("cdn", "cfl.dropboxstatic.com")],
                "tcp": [443], "udp": [], "download": ""},
    "mega": {"name": "MEGA", "aliases": ["meganz"], "category": "storage",
             "hosts": [("web", "mega.nz"), ("web", "mega.io"), ("api", "g.api.mega.co.nz"), ("cdn", "eu.static.mega.co.nz")],
             "tcp": [443], "udp": [], "download": ""},
    "notion": {"name": "Notion / Figma / Canva", "aliases": ["figma", "canva"], "category": "productivity",
               "hosts": [("web", "notion.so"), ("api", "www.notion.so"), ("web", "figma.com"), ("api", "api.figma.com"), ("web", "canva.com"), ("cdn", "static.canva.com")],
               "tcp": [443], "udp": [], "download": ""},
    # ── education ──
    "eba": {"name": "EBA (MEB)", "aliases": ["meb"], "category": "education",
            "hosts": [("web", "eba.gov.tr"), ("web", "www.eba.gov.tr"), ("api", "giris.eba.gov.tr"), ("cdn", "static.eba.gov.tr"), ("web", "meb.gov.tr")],
            "tcp": [443], "udp": [], "download": ""},
    "duolingo": {"name": "Duolingo", "aliases": [], "category": "education",
                 "hosts": [("web", "duolingo.com"), ("web", "www.duolingo.com"), ("api", "android-api-cf.duolingo.com"), ("cdn", "d35aaqx5ub95lt.cloudfront.net")],
                 "tcp": [443], "udp": [], "download": ""},
    "khan": {"name": "Khan Academy / Coursera / edX", "aliases": ["khanacademy", "coursera", "edx", "udemy"], "category": "education",
             "hosts": [("web", "khanacademy.org"), ("cdn", "cdn.kastatic.org"), ("web", "coursera.org"), ("api", "api.coursera.org"), ("web", "edx.org"), ("web", "udemy.com")],
             "tcp": [443], "udp": [], "download": ""},
    "wikipedia_full": {"name": "Wikipedia (all languages)", "aliases": ["wikimedia"], "category": "info",
                       "hosts": [("web", "wikipedia.org"), ("web", "tr.wikipedia.org"), ("web", "en.wikipedia.org"), ("cdn", "upload.wikimedia.org"), ("api", "api.wikimedia.org"), ("web", "commons.wikimedia.org")],
                       "tcp": [443], "udp": [], "download": "https://upload.wikimedia.org/wikipedia/commons/3/3f/Fronalpstock_big.jpg"},
    # ── shopping / finance ──
    "trendyol": {"name": "Trendyol / Hepsiburada", "aliases": ["hepsiburada"], "category": "shopping",
                 "hosts": [("web", "trendyol.com"), ("web", "www.trendyol.com"), ("cdn", "cdn.dsmcdn.com"), ("web", "hepsiburada.com"), ("cdn", "productimages.hepsiburada.net")],
                 "tcp": [443], "udp": [], "download": ""},
    "amazon": {"name": "Amazon / eBay / AliExpress", "aliases": ["ebay", "aliexpress", "temu"], "category": "shopping",
               "hosts": [("web", "amazon.com"), ("web", "amazon.com.tr"), ("cdn", "m.media-amazon.com"), ("web", "ebay.com"), ("web", "aliexpress.com"), ("cdn", "ae01.alicdn.com"), ("web", "temu.com")],
               "tcp": [443], "udp": [], "download": ""},
    "paypal": {"name": "PayPal / Wise / Binance", "aliases": ["wise", "binance", "coinbase", "crypto"], "category": "finance",
               "hosts": [("web", "paypal.com"), ("api", "api-m.paypal.com"), ("web", "wise.com"), ("web", "binance.com"), ("api", "api.binance.com"), ("web", "coinbase.com"), ("api", "api.coinbase.com")],
               "tcp": [443], "udp": [], "download": ""},
    # ── dev ──
    "gitlab": {"name": "GitLab / Codeberg / Bitbucket", "aliases": ["codeberg", "bitbucket"], "category": "dev",
               "hosts": [("web", "gitlab.com"), ("api", "registry.gitlab.com"), ("web", "codeberg.org"), ("web", "bitbucket.org"), ("api", "api.bitbucket.org")],
               "tcp": [443, 22], "udp": [], "download": ""},
    "pypi": {"name": "PyPI / npm / Docker Hub", "aliases": ["npm", "docker", "dockerhub", "pip"], "category": "dev",
             "hosts": [("web", "pypi.org"), ("cdn", "files.pythonhosted.org"), ("web", "npmjs.com"), ("api", "registry.npmjs.org"), ("web", "hub.docker.com"), ("api", "registry-1.docker.io"), ("cdn", "production.cloudflare.docker.com")],
             "tcp": [443], "udp": [], "download": "https://files.pythonhosted.org/packages/source/n/numpy/numpy-1.26.4.tar.gz"},
    "vscode": {"name": "VS Code / Copilot", "aliases": ["githubcopilot"], "category": "dev",
               "hosts": [("web", "code.visualstudio.com"), ("api", "update.code.visualstudio.com"), ("api", "marketplace.visualstudio.com"), ("api", "api.githubcopilot.com"), ("cdn", "vscode.blob.core.windows.net")],
               "tcp": [443], "udp": [], "download": "https://update.code.visualstudio.com/latest/win32-x64-user/stable"},
    "cursor": {"name": "Cursor / Replit / Codespaces", "aliases": ["replit", "codespaces"], "category": "dev",
               "hosts": [("web", "cursor.com"), ("api", "api2.cursor.sh"), ("web", "replit.com"), ("api", "api.replit.com"), ("web", "github.dev")],
               "tcp": [443], "udp": [], "download": ""},
    "linux": {"name": "Linux mirrors (Debian/Arch/Ubuntu)", "aliases": ["apt", "pacman", "debian", "arch", "ubuntu"], "category": "dev",
              "hosts": [("cdn", "deb.debian.org"), ("cdn", "security.debian.org"), ("cdn", "archive.ubuntu.com"), ("cdn", "geo.mirror.pkgbuild.com"), ("web", "archlinux.org"), ("cdn", "kernel.org")],
              "tcp": [443, 80], "udp": [], "download": "https://deb.debian.org/debian/ls-lR.gz"},
    # ── news ──
    "bbc": {"name": "BBC / DW / Reuters", "aliases": ["dw", "reuters", "news"], "category": "news",
            "hosts": [("web", "bbc.com"), ("web", "bbc.co.uk"), ("cdn", "ichef.bbci.co.uk"), ("web", "dw.com"), ("web", "reuters.com"), ("web", "apnews.com")],
            "tcp": [443], "udp": [], "download": ""},
    "trnews": {"name": "Turkish independent news", "aliases": ["haber", "bianet", "t24", "medyascope"], "category": "news-tr",
               "hosts": [("web", "bianet.org"), ("web", "t24.com.tr"), ("web", "medyascope.tv"), ("web", "gazeteduvar.com.tr"), ("web", "diken.com.tr"), ("web", "birgun.net"), ("web", "evrensel.net")],
               "tcp": [443], "udp": [], "download": ""},
    "eksisozluk": {"name": "Ekşi Sözlük", "aliases": ["eksi"], "category": "social",
                   "hosts": [("web", "eksisozluk.com"), ("web", "eksisozluk.com"), ("cdn", "cdn.eksisozluk.com"), ("web", "eksisozluk1923.com")],
                   "tcp": [443], "udp": [], "download": ""},
    "wattpad": {"name": "Wattpad / Archive of Our Own", "aliases": ["ao3"], "category": "social",
                "hosts": [("web", "wattpad.com"), ("api", "api.wattpad.com"), ("cdn", "img.wattpad.com"), ("web", "archiveofourown.org")],
                "tcp": [443], "udp": [], "download": ""},
    "imgur": {"name": "Imgur / Giphy / Tenor", "aliases": ["giphy", "tenor"], "category": "social",
              "hosts": [("web", "imgur.com"), ("cdn", "i.imgur.com"), ("web", "giphy.com"), ("cdn", "media.giphy.com"), ("api", "tenor.googleapis.com"), ("cdn", "media.tenor.com")],
              "tcp": [443], "udp": [], "download": ""},
    "speedtest": {"name": "Speedtest.net / fast.com", "aliases": ["ookla", "fast"], "category": "info",
                  "hosts": [("web", "speedtest.net"), ("web", "www.speedtest.net"), ("api", "www.speedtest.net"), ("web", "fast.com"), ("api", "api.fast.com")],
                  "tcp": [443, 8080], "udp": [], "download": "fast.com"},
}


def _merge_user_profiles():
    """~/.filterscope/services.json → extra/overridden profiles (same shape as SERVICES)."""
    import json
    import os
    try:
        from .config import DIR
        path = os.path.join(DIR, "services.json")
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
        for k, v in (user or {}).items():
            if not isinstance(v, dict) or not v.get("hosts"):
                continue
            v.setdefault("name", k)
            v.setdefault("aliases", [])
            v.setdefault("category", "custom")
            v.setdefault("tcp", [])
            v.setdefault("udp", [])
            v.setdefault("download", "")
            v["hosts"] = [tuple(h) for h in v["hosts"]]
            v["user"] = True
            SERVICES[k.lower()] = v
    except Exception:
        pass


USER_TEMPLATE = {
    "myschoolportal": {
        "name": "My School Portal", "aliases": ["portal"], "category": "custom",
        "hosts": [["web", "portal.example.edu"], ["api", "api.example.edu"], ["game", "game.example.edu", "tcp:9339"]],
        "tcp": [443, 9339], "udp": [[27000, 27100]], "download": "https://example.edu/big-file.zip",
    }
}

_merge_user_profiles()


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
