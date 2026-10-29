#!/usr/bin/env python3
"""Собирает самодостаточный установщик «Мой дом» (все исходники внутри .command).

Запуск из корня репозитория:  python3 tools/make_installer.py
Результат: папка dist/ (установщик, деинсталлятор, инструкция, zip).

Установщик компилирует исходники на компьютере пользователя (swiftc), поэтому в нём нет готовых
бинарников, а для запуска не нужны Xcode и аккаунт разработчика — достаточно Command Line Tools.
"""
import os, re, zipfile
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
srcdir = os.path.join(root, 'Sources')
# Приложение компилируется как один файл (в нём есть код верхнего уровня), поэтому файлы склеиваются.
parts = ['Icons.swift', 'YaHome.swift']
src = '\n'.join(open(os.path.join(srcdir, p), encoding='utf-8').read() for p in parts)
ver = re.search(r'let appVersion = "([^"]+)"', src).group(1)
author = re.search(r'let appAuthor = "([^"]+)"', src).group(1)
assert 'YAHOME_SOURCE_EOF' not in src
here = root
installer = r'''#!/bin/bash
# Мой дом __VER__ — управление умным домом Яндекса из строки меню macOS
# Автор: __AUTHOR__ · Неофициальный проект, не связан с компанией Яндекс.
VERSION="__VER__"
APP="$HOME/Applications/YaHome.app"
AGENT="$HOME/Library/LaunchAgents/local.yahome.menubar.plist"

pause() { read -n1 -s -r -p "Нажмите любую клавишу, чтобы закрыть окно..."; echo; }

echo "== Мой дом $VERSION · __AUTHOR__ =="
echo

MAJOR=$(sw_vers -productVersion | cut -d. -f1)
if [ "$MAJOR" -lt 13 ]; then
  echo "Нужна macOS 13 или новее (у вас $(sw_vers -productVersion))."
  pause; exit 1
fi

if ! xcrun --find swiftc >/dev/null 2>&1; then
  echo "Для установки нужны Command Line Tools от Apple (бесплатно, 1–2 ГБ)."
  echo "Сейчас появится окно macOS: нажмите «Установить» и дождитесь окончания."
  xcode-select --install >/dev/null 2>&1
  # ждём не бесконечно: если окно закрыли или нажали «Отмена», установка не пойдёт
  WAITED=0
  until xcrun --find swiftc >/dev/null 2>&1; do
    sleep 5; WAITED=$((WAITED + 5))
    if [ "$WAITED" -ge 1800 ]; then break; fi
  done
  if ! xcrun --find swiftc >/dev/null 2>&1; then
    echo
    echo "Command Line Tools не установлены (установка отменена или не завершилась)."
    echo "Запустите в Терминале: xcode-select --install — и повторите этот установщик."
    pause; exit 1
  fi
  echo "Command Line Tools установлены."
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/YaHome.swift" <<'YAHOME_SOURCE_EOF'
__SOURCE__
YAHOME_SOURCE_EOF

pkill -x YaHome 2>/dev/null
mkdir -p "$APP/Contents/MacOS" "$HOME/Applications"

cat > "$APP/Contents/Info.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>YaHome</string>
<key>CFBundleIdentifier</key><string>local.yahome.menubar</string>
<key>CFBundleName</key><string>Мой дом</string>
<key>CFBundleDisplayName</key><string>Мой дом</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundleVersion</key><string>$VERSION</string>
<key>NSHumanReadableCopyright</key><string>__AUTHOR__</string>
<key>LSUIElement</key><true/>
</dict></plist>
PL

echo "Сборка приложения (1–2 минуты)..."
if ! swiftc -O -suppress-warnings "$TMP/YaHome.swift" -o "$APP/Contents/MacOS/YaHome"; then
  echo
  echo "Ошибка сборки. Скопируйте текст выше и отправьте автору."
  pause; exit 1
fi
# стабильная подпись: токен в связке ключей не запрашивает пароль после обновлений
REQ='designated => identifier "local.yahome.menubar"'
if ! codesign --force --sign - --identifier local.yahome.menubar -r="$REQ" "$APP" >/dev/null 2>&1; then
  if ! codesign --force --sign - "$APP" >/dev/null 2>&1; then
    echo "Не удалось подписать приложение (codesign). Приложение может не запуститься."
    pause; exit 1
  fi
  echo "Предупреждение: подпись без фиксированного идентификатора — macOS может запросить пароль к связке ключей."
fi

if [ ! -f "$AGENT" ]; then
  read -p "Запускать виджет автоматически при входе в систему? [y/N] " A
  if [[ "$A" == "y" || "$A" == "Y" ]]; then
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$AGENT" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.yahome.menubar</string>
<key>ProgramArguments</key><array><string>$APP/Contents/MacOS/YaHome</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PL
    STARTED=0
    if launchctl bootstrap "gui/$(id -u)" "$AGENT" >/dev/null 2>&1; then
      STARTED=1
      echo "Автозапуск включён и загружен."
    else
      echo "Автозапуск записан, но сейчас не загрузился; он сработает при следующем входе в систему."
    fi
  fi
fi

if [ "${STARTED:-0}" != "1" ]; then
  if ! open "$APP"; then echo "Не удалось запустить приложение: $APP"; pause; exit 1; fi
fi
echo
echo "Готово. В строке меню должен появиться домик."
echo "• Клик по домику — устройства по комнатам, сценарии Алисы."
echo "• Первый раз нажмите «Войти через Яндекс» и подтвердите доступ в браузере."
sleep 4
'''
installer = installer.replace('__VER__', ver).replace('__AUTHOR__', author).replace('__SOURCE__', src.rstrip('\n'))

uninstaller = r'''#!/bin/bash
# Удаление виджета «Мой дом»
pkill -x YaHome 2>/dev/null
launchctl bootout "gui/$(id -u)/local.yahome.menubar" 2>/dev/null || launchctl unload "$HOME/Library/LaunchAgents/local.yahome.menubar.plist" 2>/dev/null
rm -f "$HOME/Library/LaunchAgents/local.yahome.menubar.plist"
rm -rf "$HOME/Applications/YaHome.app"
security delete-generic-password -s local.yahome.menubar >/dev/null 2>&1
echo "Мой дом удалён (приложение, автозапуск, токен в связке ключей)."
HIST="$HOME/Library/Application Support/YaHome"
if [ -d "$HIST" ]; then
  read -p "Удалить ещё и сохранённую историю датчиков ($HIST)? [y/N] " A
  if [[ "$A" == "y" || "$A" == "Y" ]]; then rm -rf "$HIST"; echo "История удалена."; fi
fi
sleep 2
'''

readme = f'''Мой дом {ver} — умный дом Яндекса (Алиса) в строке меню macOS
Автор: {author}

Показывает устройства по комнатам: включение и выключение, яркость, температура, показания датчиков, сценарии Алисы.
Работает через открытый API Яндекса. Токен хранится в связке ключей этого Mac.

НЕОФИЦИАЛЬНЫЙ ПРОЕКТ: не связан с компанией Яндекс и не одобрен ею. «Яндекс», «Алиса», «Станция» —
товарные знаки их владельцев, упоминаются только для описания совместимости. Подробнее — NOTICE.md в репозитории.

КАК УСТАНОВИТЬ
1. Правый клик по «Установить Мой дом.command» → «Открыть» → подтвердите.
2. При первом запуске нажмите «Войти через Яндекс» и подтвердите доступ в браузере.

КАК ОБНОВИТЬ: запустите новый установщик. КАК УДАЛИТЬ: «Удалить Мой дом.command».
Требуется macOS 13 или новее.
'''

dist = os.path.join(here, 'dist')
os.makedirs(dist, exist_ok=True)
files = {
    'Установить Мой дом.command': installer,
    'Удалить Мой дом.command': uninstaller,
    'Как установить.txt': readme,
}
for extra in ('NOTICE.md', 'LICENSE'):
    ep = os.path.join(here, extra)
    if os.path.exists(ep):
        files[extra] = open(ep, encoding='utf-8').read()
for name, body in files.items():
    p = os.path.join(dist, name)
    open(p, 'w', encoding='utf-8').write(body)
    if name.endswith('.command'):
        os.chmod(p, 0o755)
zpath = os.path.join(dist, f'YaHome-{ver}.zip')
with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
    for name in files:
        zi = zipfile.ZipInfo(name)
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = (0o755 if name.endswith('.command') else 0o644) << 16
        z.writestr(zi, open(os.path.join(dist, name), 'rb').read())
print('версия', ver, '->', dist)
