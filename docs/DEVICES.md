# Поддерживаемые устройства

Приложение показывает **всё, что вернул Яндекс** в `/user/info`. Устройства сторонних производителей (Xiaomi, Tuya/Smart Life,
Aqara, Philips Hue, Redmond, Polaris, Roborock, Dreame, Sonoff и многие другие) попадают туда через навыки в приложении
«Дом с Алисой» и приходят в виде тех же типов `devices.types.*` — поэтому отдельной поддержки брендов не нужно.
Список подключаемых производителей смотрите в приложении Яндекса; ниже — как каждый тип выглядит здесь.

Тип в таблице — без префикса `devices.types.`. «Категория» — это фильтр-чип сверху; «Значок» — SF Symbols
(первый доступный по списку, чтобы на старых macOS был запасной вариант).

| Тип Яндекса | Категория | Значок (основной → запасные) |
|---|---|---|
| `light`, `light.ceiling`, `light.strip` | Свет | `lightbulb.fill`; потолочные `lamp.ceiling.fill`; ленты `lightbulb.led.fill`; торшеры/настольные `lamp.floor.fill`, `lamp.table.fill` |
| `socket` | Розетки | `powerplug.fill` |
| `switch`, `switch.relay` | Выключатели | `switch.2` |
| `thermostat`, `thermostat.ac` | Климат | кондиционер `air.conditioner.horizontal.fill`; обогреватель `heater.vertical.fill`; иначе `thermometer.medium` |
| `humidifier` | Климат | `humidifier.and.droplets.fill` → `humidity.fill` |
| `purifier` | Климат | `air.purifier.fill` → `wind` |
| `fan`, `ventilation*` | Климат | `fan.fill` → `wind` |
| `media_device.tv` | ТВ и колонки | `tv.fill` |
| `media_device.tv_box` | ТВ и колонки | `appletv.fill` → `tv` |
| `media_device.receiver` | ТВ и колонки | `hifispeaker.2.fill` → `hifispeaker.fill` |
| `media_device` (проектор и др.) | ТВ и колонки | `videoprojector.fill` / `hifispeaker.fill` |
| `smart_speaker*` (Станции) | ТВ и колонки | `homepod.fill` → `hifispeaker.fill` |
| `cooking.kettle` | Кухня | `cup.and.saucer.fill` |
| `cooking.coffee_maker` | Кухня | `mug.fill` → `cup.and.saucer.fill` |
| `cooking.multicooker` | Кухня | `frying.pan.fill` → `fork.knife` |
| `cooking` (духовка и др.) | Кухня | `oven.fill` → `fork.knife` |
| `vacuum_cleaner` | Уборка и стирка | `robotic.vacuum.fill` → `sparkles` |
| `washing_machine` | Уборка и стирка | `washer.fill` |
| `dishwasher` | Уборка и стирка | `dishwasher.fill` → `sparkles` |
| `iron` | Уборка и стирка | `flame.fill` |
| `openable.curtain` | Шторы и двери | `blinds.horizontal.closed` → `window.shade.closed` |
| `openable.valve` | Шторы и двери | `spigot.fill` → `drop.fill` |
| `openable` (ворота, замок, дверь) | Шторы и двери | `door.garage.closed` / `lock.fill` / `door.left.hand.closed` |
| `sensor.motion` | Датчики | `figure.walk.motion` → `figure.walk` |
| `sensor.open` | Датчики | `door.left.hand.open` |
| `sensor.button` | Датчики | `button.programmable` |
| `sensor.smoke` | Датчики | `smoke.fill` → `flame.fill` |
| `sensor.gas` | Датчики | `aqi.medium` |
| `sensor.vibration` | Датчики | `waveform.path` |
| `sensor.illumination` | Датчики | `sun.max.fill` |
| `sensor.water_leak` | Датчики | `drop.triangle.fill` → `drop.fill` |
| `sensor.climate`, `sensor` | Датчики | `thermometer.medium` / `sensor.fill` |
| `camera` | Камеры | `web.camera.fill` → `video.fill` |
| `smart_meter.electricity` | Счётчики | `bolt.fill` |
| `smart_meter.gas` | Счётчики | `flame.fill` |
| `smart_meter.cold_water`, `.hot_water` | Счётчики | `drop.fill` |
| `smart_meter.heat` | Счётчики | `thermometer.sun.fill` |
| `smart_meter` | Счётчики | `gauge.medium` |
| `pet_feeder` | Питомцы | `pawprint.fill` |
| `pet_drinking_fountain` | Питомцы | `drop.fill` → `pawprint.fill` |
| `hub` | Прочее | `wifi.router.fill` |
| `other` и неизвестные | по названию, иначе Прочее | см. ниже |

## Определение по названию
Если тип — `other` или не распознан, категория и значок подбираются по словам в названии (регистр не важен):
*лампа, светильник, люстра, торшер, лента, подсветка, ночник → Свет; розетка → Розетки; выключатель; кондиционер,
обогреватель, радиатор, конвектор, тёплый пол, увлажнитель, очиститель, вентилятор → Климат; телевизор, приставка,
колонка, станция, проектор, ресивер, саундбар → ТВ и колонки; чайник, кофе, мультиварка, духовка, плита,
холодильник → Кухня; пылесос, стиральная, посудомоечная, утюг → Уборка; штора, жалюзи, ворота, замок, дверь,
клапан → Шторы и двери; датчик; камера; счётчик; кормушка, поилка → Питомцы.*

## Как это показывается
1. Если у устройства есть готовая растровая картинка (`Icons.iconData`) — она.
2. Иначе — нарисованная иконка устройства (слои с градиентами, без внешних файлов). Для включённых горит подсветка,
   выключенные тусклые. Нарисованы: станции (Лайт, Мини, Миди, Станция, Макс, Стрит), лампочка, настольная лампа, торшер,
   потолочный светильник, лента, розетка, выключатель, ИК-пульт, ТВ, приставка, саундбар/ресивер, проектор, кондиционер,
   обогреватель, вентилятор, увлажнитель, очиститель, пылесос, чайник, кофемашина, мультиварка, духовка, холодильник,
   стиральная и посудомоечная машины, утюг, шторы, кран, ворота, замок, камера, хаб, кормушка и поилка, все виды датчиков
   (движение, дверь/окно, кнопка, дым, газ, вибрация, освещённость, протечка, климат) и счётчики (электричество, газ, вода, тепло).
3. Для остальных устройств — скруглённая плашка цвета категории со значком SF Symbols.
4. Выключенные и недоступные устройства — тусклые.

## Как добавить своё устройство
1. Узнайте тип устройства: он есть в ответе `GET /user/info` (поле `devices[].type`) — запрос можно выполнить через curl со своим токеном (токен никому не показывайте).
2. Добавьте ветку в `Dev.symbol` (список кандидатов, первый существующий берётся автоматически) и,
   если нужна новая категория, строку в `allCats` и условие в `Dev.cat`.
3. Откройте pull request и приложите тип и название (без токенов и ID).

## Что показывается в строке состояния плитки
Подпись зависит от возможностей: яркость и цвет у света, целевая температура у климата, прогресс у чайника и
процессов (уборка, стирка), температура/влажность/заряд батареи/мощность/CO₂ у датчиков.
