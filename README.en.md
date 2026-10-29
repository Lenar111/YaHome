# Мой дом (YaHome) — Yandex Smart Home for the macOS menu bar

A small native Swift app that shows your **Yandex Smart Home (Alice)** devices in the Mac menu bar:
rooms, one-click control, scenarios, sensor readings and a **complete, never-expiring history** of temperature,
humidity, CO₂ and pressure that you can browse by day, week, month, year or any custom range.

> Unofficial project, not affiliated with or endorsed by Yandex. "Yandex", "Alice" and related names are trademarks of their owners and are used only to describe compatibility. The app uses the public Yandex Smart Home API; the repository contains no Yandex logos or artwork. See [NOTICE.md](NOTICE.md). The UI is in Russian.

- macOS 13+, no third-party dependencies, single Swift source file compiled by plain `swiftc`.
- Login via Yandex OAuth (or paste your own token); the token lives in the macOS Keychain.
- Talks only to `api.iot.yandex.net` and `oauth.yandex.ru`.
- Icons/categories for all Yandex device types and for third-party devices linked through Yandex.

Install: download the release zip → right-click *Install* `.command` → *Open*. The app is compiled locally
(Command Line Tools are enough; Xcode is not required). From source: `python3 tools/make_installer.py`
or `tools/build.sh`. See `docs/` for architecture, auth, devices and statistics. MIT license.
