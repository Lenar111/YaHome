# Публикация на GitHub

## 0. Проверка перед публикацией
- [ ] В репозитории нет токенов, паролей, ID устройств, адресов (поиск: `grep -rniE "token|y0_|password" .`).
- [ ] Картинки устройств: в `Sources/Icons.swift` словарь пуст — чужая графика не публикуется. Свою добавляйте только если права на неё ваши.
- [ ] `clientID` в `Sources/YaHome.swift` — ваш публичный OAuth ID (см. [AUTH.md](AUTH.md)); для форков лучше зарегистрировать свой.
- [ ] Скриншоты без личных названий.
- [ ] В README и NOTICE.md есть пометка «неофициальный проект, не связан с Яндексом»; логотипов Яндекса нигде нет.
- [ ] Установщик с вашими личными PNG-иконками (если такой есть) в релиз не кладите — только `YaHome-*-release.zip`, собранный из этих исходников.

## 1. Создайте репозиторий
1. https://github.com/new → Repository name: `YaHome` (или `yahome-macos`).
2. Description: «Умный дом Яндекса (Алиса) в строке меню macOS — нативный Swift, история датчиков без ограничения по сроку».
3. **Public**. Галочки «Add a README / .gitignore / license» **не ставьте** — они уже есть в папке.

## 2. Загрузите файлы (терминал)
```bash
cd ~/путь/к/YaHome                      # папка из архива
git init -b main
git config user.name  "Ваше Имя"
git config user.email "ID+логин@users.noreply.github.com"   # адрес-«заглушка» из github.com/settings/emails
git add .
git commit -m "Первая публикация: Мой дом 1.10.0"
git remote add origin https://github.com/<логин>/YaHome.git
git push -u origin main
```
Если спросит пароль — GitHub принимает не пароль, а токен. Проще всего поставить GitHub CLI (`brew install gh`), выполнить
`gh auth login` и повторить `git push`. Через CLI всё можно сделать одной командой:
```bash
gh repo create YaHome --public --source=. --remote=origin --push
```
**Без терминала:** на странице пустого репозитория нажмите *uploading an existing file*, перетащите *содержимое* папки
(включая скрытую `.github`) и нажмите *Commit changes*. (Папки с точкой в имени проще загружать через терминал.)

## 3. Оформите страницу
- ⚙︎ *About* справа: описание, **Topics** — `macos`, `menubar`, `swift`, `swiftui`, `smart-home`, `yandex`, `alice`, `iot`.
- *Settings → General → Features*: включите **Issues**; *Security → Private vulnerability reporting* — включите.
- Скриншоты → `docs/images/` и в корневой `README.md`.

## 4. Проверьте сборку (CI)
Вкладка **Actions**: workflow `build` соберёт проект на macOS-раннере (проверка типов, сборка, установщик).
Автор до публикации не мог запустить компилятор Swift в своей среде — **если CI покажет ошибки, это ожидаемо:** пришлите
текст ошибки, она исправляется в одной-двух строках.

## 5. Релиз с установщиком
```bash
python3 tools/make_installer.py            # → dist/YaHome-1.10.0.zip
git tag v1.10.0 && git push origin v1.10.0
gh release create v1.10.0 dist/YaHome-1.10.0.zip \
  --title "Мой дом 1.10.0" --notes-file CHANGELOG.md
```
Или в веб-интерфейсе: *Releases → Draft a new release* → тег `v1.10.0` → приложите zip → *Publish*.
В описании релиза напишите: требуется macOS 13+; сборка происходит на вашем Mac, нужны Command Line Tools.

## 6. Дальше
- Выпуск новой версии: поднять `appVersion`, дописать `CHANGELOG.md`, `make_installer.py`, тег, релиз.
- Просьбы про устройства — в Issues с шаблоном: «тип устройства / название / что показывается не так».
- Платное распространение и подпись нотариусом (чтобы не нажимать «Открыть» по правому клику) требуют аккаунта Apple Developer — не обязательно.
