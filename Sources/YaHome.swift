import Cocoa
import SwiftUI
import Network
import Security

// «Мой дом» — неофициальный клиент умного дома Яндекса из строки меню macOS.
// Проект не связан с компанией Яндекс и не одобрен ею. «Яндекс», «Алиса» и связанные
// названия принадлежат их владельцам и упоминаются только для описания совместимости.
// Работает через открытый API: https://api.iot.yandex.net/v1.0

let appVersion = "1.10.4"
let appAuthor = "Lenar Abdrakhmanov"
// Публичный ID OAuth-приложения автора (не секрет). Свой ID можно задать без пересборки:
//   defaults write local.yahome.menubar clientID "ВАШ_ID"
let defaultClientID = "38251f0a02ca44a0b84cd3494b462174"
var clientID: String {
    let v = UserDefaults.standard.string(forKey: "clientID")?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return v.isEmpty ? defaultClientID : v
}
let loopPort: UInt16 = 8765
let redirectURI = "http://127.0.0.1:8765/callback"
let apiBase = "https://api.iot.yandex.net/v1.0"

// MARK: - Хранилище токена (связка ключей macOS)

enum Keychain {
    static let service = "local.yahome.menubar"
    private static func base() -> [String: Any] {
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: "token"]
    }
    static func get() -> String? {
        var q = base()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var r: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &r) == errSecSuccess, let d = r as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }
    /// true — операция удалась (для удаления «не найдено» тоже успех)
    @discardableResult
    static func set(_ v: String?) -> Bool {
        let del = SecItemDelete(base() as CFDictionary)
        guard del == errSecSuccess || del == errSecItemNotFound else { return false }
        guard let v = v else { return true }
        guard let d = v.data(using: .utf8) else { return false }
        var a = base()
        a[kSecValueData as String] = d
        a[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        return SecItemAdd(a as CFDictionary, nil) == errSecSuccess
    }
}

// MARK: - Локальный приёмник ответа Яндекса (вход через браузер)

final class AuthServer {
    private var listener: NWListener?
    var onToken: ((String) -> Void)?
    /// одноразовый параметр state: токен принимается только с ним (защита от подброшенного запроса)
    var expectedState = ""
    /// вызывается, если приёмник упал уже после запуска (например, порт заняли в последний момент)
    var onFail: ((String) -> Void)?
    private var timeout: DispatchWorkItem?
    private var readyHandler: (() -> Void)?

    /// Синхронная проверка, что 127.0.0.1:порт свободен (NWListener сообщает об ошибке только асинхронно).
    private static func portIsFree(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr = in_addr(s_addr: UInt32(0x7F000001).bigEndian)
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        return r == 0
    }

    /// false — приёмник не запустился (например, порт занят); тогда вход через браузер не начинаем
    /// `onReady` вызывается, только когда приёмник реально принимает соединения (состояние `.ready`).
    @discardableResult
    func start(onReady: @escaping () -> Void) -> Bool {
        stop()
        guard AuthServer.portIsFree(loopPort) else { return false }
        let p = NWParameters.tcp
        p.requiredInterfaceType = .loopback
        guard let port = NWEndpoint.Port(rawValue: loopPort), let l = try? NWListener(using: p, on: port) else { return false }
        l.newConnectionHandler = { [weak self] c in self?.handle(c) }
        readyHandler = onReady
        l.stateUpdateHandler = { [weak self, weak l] st in
            switch st {
            case .ready:
                if self?.listener === l, let h = self?.readyHandler { self?.readyHandler = nil; h() }
            case .failed, .cancelled:
                if self?.listener === l {
                    l?.cancel()
                    self?.listener = nil
                    self?.timeout?.cancel()
                    self?.onFail?("Приёмник входа остановился (порт \(loopPort)). Повторите вход или вставьте токен вручную.")
                }
            default: break
            }
        }
        listener = l
        l.start(queue: .main)
        timeout?.cancel()
        let w = DispatchWorkItem { [weak self] in
            guard let self = self, self.listener != nil else { return }
            self.stop()
            self.onFail?("Время ожидания входа истекло (10 минут). Нажмите «Войти» ещё раз.")
        }
        timeout = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 600, execute: w)
        return true
    }

    func stop() {
        timeout?.cancel()
        timeout = nil
        readyHandler = nil
        let l = listener
        listener = nil          // сначала сбрасываем, чтобы обработчик состояния не считал остановку сбоем
        l?.cancel()
    }

    private func handle(_ c: NWConnection) {
        c.start(queue: .main)
        c.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, _, _ in
            guard let self = self, let data = data, let text = String(data: data, encoding: .utf8) else { c.cancel(); return }
            let first = text.components(separatedBy: "\r\n").first ?? ""
            let parts = first.components(separatedBy: " ")
            let path = parts.count > 1 ? parts[1] : "/"
            var body = ""
            var status = "200 OK"
            if path.hasPrefix("/t?") {
                let q = String(path.dropFirst(3))
                if !self.expectedState.isEmpty, AuthServer.param(q, "state") == self.expectedState,
                   let t = AuthServer.extractToken(q) {
                    self.expectedState = ""
                    self.onToken?(t)
                    body = "ok"
                } else {
                    status = "403 Forbidden"
                    body = "bad state"
                }
            } else {
                body = AuthServer.page
            }
            let bytes = Array(body.utf8)
            let head = "HTTP/1.1 \(status)\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(bytes.count)\r\nConnection: close\r\n\r\n"
            var out = Data(head.utf8)
            out.append(contentsOf: bytes)
            c.send(content: out, completion: .contentProcessed { _ in c.cancel() })
        }
    }

    static func param(_ s: String, _ key: String) -> String? {
        for part in s.split(whereSeparator: { $0 == "&" || $0 == "?" || $0 == "#" }) {
            let kv = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if kv.count == 2, kv[0] == key { return String(kv[1]) }
        }
        return nil
    }

    static func extractToken(_ s: String) -> String? {
        guard let r = s.range(of: "access_token=") else { return nil }
        let rest = s[r.upperBound...]
        let tok = rest.prefix { $0 != "&" && $0 != " " && $0 != "\n" && $0 != "\r" }
        return tok.isEmpty ? nil : String(tok)
    }

    static let page = """
    <!doctype html><meta charset="utf-8"><title>Мой дом</title>
    <body style="font:22px -apple-system,Helvetica,Arial;text-align:center;margin-top:22vh;color:#222">
    <div id="m">Подключаю…</div>
    <script>
    var h = location.hash.slice(1);
    var m = document.getElementById('m');
    if (h.indexOf('access_token') >= 0) {
      fetch('/t?' + h).then(function (r) { m.textContent = r.ok ? 'Готово. Вернитесь в виджет — эту вкладку можно закрыть.' : 'Вход отклонён: неверный или устаревший запрос. Нажмите «Войти» в виджете ещё раз.'; });
    } else {
      m.textContent = 'Не удалось получить доступ. ' + (location.search || h || '');
    }
    </script></body>
    """
}

// MARK: - Модели

struct RangeCap {
    var instance: String
    var value: Double
    var min: Double
    var max: Double
    var step: Double
    var unit: String
}

struct ModeCap {
    var instance: String
    var values: [String]
    var value: String
}

struct ToggleCap {
    var instance: String
    var value: Bool
}

struct ColorCap {
    var model = ""
    var rgb = 0
    var hasTK = false
    var tkMin = 2700.0
    var tkMax = 6500.0
    var tk = 4000.0
    var scenes: [String] = []
    var scene = ""
    var current = ""
}

struct Prop {
    var instance: String
    var value: Double
    var updated: Double = 0
}

/// «5 мин назад»
func ageText(_ secs: Double) -> String {
    if secs < 90 { return "только что" }
    let m = Int(secs / 60)
    if m < 60 { return "\(m) мин назад" }
    let h = m / 60
    if h < 24 { return "\(h) ч назад" }
    return "давно"
}

func dnum(_ a: Any?) -> Double? { return (a as? NSNumber)?.doubleValue }

/// цвет из тона (0–360), насыщенности и яркости (0–1) в число RGB
func rgbInt(h: Double, s: Double, v: Double) -> Int {
    let c = v * s
    let hh = h / 60.0
    let x = c * (1 - abs(hh.truncatingRemainder(dividingBy: 2) - 1))
    var r = 0.0, g = 0.0, b = 0.0
    switch Int(hh) % 6 {
    case 0: r = c; g = x
    case 1: r = x; g = c
    case 2: g = c; b = x
    case 3: g = x; b = c
    case 4: r = x; b = c
    default: r = c; b = x
    }
    let m = v - c
    let R = Int(((r + m) * 255).rounded()), G = Int(((g + m) * 255).rounded()), B = Int(((b + m) * 255).rounded())
    return (R << 16) | (G << 8) | B
}

func hueOf(_ rgb: Int) -> Double {
    let r = Double((rgb >> 16) & 255) / 255, g = Double((rgb >> 8) & 255) / 255, b = Double(rgb & 255) / 255
    let mx = Swift.max(r, Swift.max(g, b)), mn = Swift.min(r, Swift.min(g, b))
    let d = mx - mn
    if d < 0.0001 { return 0 }
    var h = 0.0
    if mx == r { h = ((g - b) / d).truncatingRemainder(dividingBy: 6) }
    else if mx == g { h = (b - r) / d + 2 }
    else { h = (r - g) / d + 4 }
    h *= 60
    return h < 0 ? h + 360 : h
}

/// возможность устройства, для которой нет готового элемента управления (например, кнопки ИК-пульта)
struct OtherCap {
    var type: String
    var instance: String
    var title: String
    /// кнопка пульта, которую можно нажать через API. «builtin_buttons» — служебная возможность станций:
    /// Яндекс не принимает по ней команды, поэтому кнопкой её не показываем
    var isButton: Bool { return type.contains("button") && !type.contains("builtin") && !instance.contains("builtin") }
}

struct Dev: Identifiable {
    var id: String
    var name: String
    var type: String
    var roomID: String
    var hhID: String
    var online: Bool
    var on: Bool?
    var ranges: [RangeCap] = []
    var modes: [ModeCap] = []
    var toggles: [ToggleCap] = []
    var color: ColorCap?
    var props: [Prop] = []
    var others: [OtherCap] = []
    var rawCaps: [String] = []

    init(raw: [String: Any]) {
        id = raw["id"] as? String ?? UUID().uuidString
        name = raw["name"] as? String ?? "Устройство"
        type = raw["type"] as? String ?? ""
        roomID = raw["room"] as? String ?? ""
        hhID = raw["household_id"] as? String ?? ""
        online = ((raw["state"] as? String) ?? "online") != "offline"
        for c in raw["capabilities"] as? [[String: Any]] ?? [] {
            let t = c["type"] as? String ?? ""
            let params = c["parameters"] as? [String: Any] ?? [:]
            let state = c["state"] as? [String: Any]
            let inst = (params["instance"] as? String) ?? (state?["instance"] as? String) ?? ""
            rawCaps.append(t.replacingOccurrences(of: "devices.capabilities.", with: "") + (inst.isEmpty ? "" : ":" + inst))
            if t == "devices.capabilities.on_off" {
                on = (state?["value"] as? Bool) ?? false
            } else if t == "devices.capabilities.range" {
                let rng = params["range"] as? [String: Any] ?? [:]
                var lo = dnum(rng["min"]) ?? 0
                var hi = dnum(rng["max"]) ?? 100
                if hi <= lo { lo = 0; hi = 100 }
                let st = dnum(rng["precision"]) ?? 1
                let unit = params["unit"] as? String ?? ""
                let u = unit.contains("percent") ? "%" : (unit.contains("temperature") ? "°" : "")
                ranges.append(RangeCap(instance: inst, value: dnum(state?["value"]) ?? lo, min: lo, max: hi, step: st > 0 ? st : 1, unit: u))
            } else if t == "devices.capabilities.mode" {
                var vals: [String] = []
                for m in params["modes"] as? [[String: Any]] ?? [] {
                    if let v = m["value"] as? String { vals.append(v) }
                }
                modes.append(ModeCap(instance: inst, values: vals, value: (state?["value"] as? String) ?? ""))
            } else if t == "devices.capabilities.toggle" {
                toggles.append(ToggleCap(instance: inst, value: (state?["value"] as? Bool) ?? false))
            } else if t == "devices.capabilities.color_setting" {
                var cc = ColorCap()
                if let cm = params["color_model"] as? String { cc.model = cm }
                if let tk = params["temperature_k"] as? [String: Any] {
                    cc.hasTK = true
                    cc.tkMin = dnum(tk["min"]) ?? 2700
                    cc.tkMax = dnum(tk["max"]) ?? 6500
                }
                if let sc = params["color_scene"] as? [String: Any] {
                    for s in sc["scenes"] as? [[String: Any]] ?? [] {
                        if let sid = s["id"] as? String { cc.scenes.append(sid) }
                    }
                }
                if let si = state?["instance"] as? String {
                    cc.current = si
                    if si == "rgb" { cc.rgb = Int(dnum(state?["value"]) ?? 0) }
                    else if si == "hsv", let hv = state?["value"] as? [String: Any] {
                        cc.rgb = rgbInt(h: dnum(hv["h"]) ?? 0, s: (dnum(hv["s"]) ?? 100) / 100, v: 1)
                        cc.current = "rgb"
                    }
                    else if si == "temperature_k" { cc.tk = dnum(state?["value"]) ?? cc.tk }
                    else if si == "scene" {
                        cc.scene = (state?["value"] as? String) ?? ""
                        
                    }
                }
                color = cc
            } else {
                let nm = (params["name"] as? String) ?? (params["instance_name"] as? String) ?? inst
                others.append(OtherCap(type: t, instance: inst, title: nm.isEmpty ? "Кнопка" : nm))
            }
        }
        if isStation { on = nil }
        if !isStation, color != nil {
            color?.scenes.removeAll { $0 == "inactive" }
            if color?.scene == "inactive" { color?.scene = ""; color?.current = "" }
        }
        for p in raw["properties"] as? [[String: Any]] ?? [] {
            let state = p["state"] as? [String: Any]
            if let inst = state?["instance"] as? String, let v = dnum(state?["value"]) {
                props.append(Prop(instance: inst, value: v, updated: dnum(p["last_updated"]) ?? 0))
            }
        }
    }

    var kind: String { return type.replacingOccurrences(of: "devices.types.", with: "") }
    /// Яндекс Станция (колонка), но не ТВ Станция
    var isStation: Bool {
        let n = name.lowercased()
        if kind.hasPrefix("media_device.tv") || n.contains("тв") { return false }
        return kind.hasPrefix("smart_speaker") || n.contains("станци")
    }
    /// у станций: включена ли световая сцена подсветки
    var stationLight: String? {
        guard isStation, let c = color, c.current == "scene", !c.scene.isEmpty, c.scene != "inactive" else { return nil }
        return c.scene
    }
    var isKettle: Bool { return kind.contains("kettle") || name.lowercased().contains("чайник") }
    var bright: RangeCap? { return ranges.first { $0.instance == "brightness" } }
    var target: RangeCap? { return ranges.first { $0.instance == "temperature" } }
    var curTemp: Double? { return props.first { $0.instance == "temperature" }?.value }
    /// сколько секунд назад устройство сообщало температуру
    var tempAge: Double? {
        guard let p = props.first(where: { $0.instance == "temperature" }), p.updated > 0 else { return nil }
        return Swift.max(0, Date().timeIntervalSince1970 - p.updated)
    }
    /// нет времени обновления — данные НЕ считаются свежими
    var tempFresh: Bool { if let a = tempAge { return a < 180 } else { return false } }
    var isProcess: Bool {
        return kind.hasPrefix("cooking") || kind.hasPrefix("vacuum") || kind.hasPrefix("washing") || kind.hasPrefix("dishwasher")
    }
    var hasControls: Bool {
        return online && (!ranges.isEmpty || !modes.isEmpty || !toggles.isEmpty || color != nil || (on == nil && !props.isEmpty))
    }

    var heating: Bool {
        guard isKettle, on == true, online else { return false }
        if let c = curTemp, let t = target { return c < t.value - 1 }
        return true
    }

    var busy: Bool {
        if isKettle { return heating }
        return isProcess && on == true && online
    }

    var progress: Double? {
        guard heating, tempFresh, let c = curTemp, let t = target else { return nil }
        return Swift.min(1, Swift.max(0.03, (c - 20) / Swift.max(1, t.value - 20)))
    }

    var statusLine: String? {
        guard online, on == true else { return nil }
        if isKettle {
            if heating {
                if let c = curTemp, let t = target, tempFresh { return "Греется · " + Dev.num(c) + "° из " + Dev.num(t.value) + "°" }
                return "Греется…"
            }
            if let c = curTemp, tempFresh { return "Готово · " + Dev.num(c) + "°" }
            if curTemp != nil { return "Включён" }
            return "Включён"
        }
        if isProcess { return "Работает" }
        return nil
    }

    /// слова из названия: помогают, когда производитель отдал устройство как «other» или общий тип
    func nameHas(_ words: [String]) -> Bool {
        let n = name.lowercased()
        for w in words where n.contains(w) { return true }
        return false
    }

    /// категория для фильтров («Свет», «Кухня», «Уборка», «Шторы и двери» …)
    var cat: String {
        let k = kind
        if k.hasPrefix("light") { return "light" }
        if k.hasPrefix("socket") { return "socket" }
        if k.hasPrefix("switch") { return "switch" }
        if k.hasPrefix("thermostat") || k.hasPrefix("humidifier") || k.hasPrefix("purifier") || k.hasPrefix("fan") || k.hasPrefix("ventilation") { return "climate" }
        if k.hasPrefix("media_device") || k.hasPrefix("tv") || k.hasPrefix("smart_speaker") { return "media" }
        if k.hasPrefix("cooking") || isKettle { return "kitchen" }
        if k.hasPrefix("vacuum") || k.hasPrefix("washing") || k.hasPrefix("dishwasher") || k.hasPrefix("iron") { return "cleaning" }
        if k.hasPrefix("openable") { return "cover" }
        if k.hasPrefix("sensor") { return "sensor" }
        if k.hasPrefix("camera") { return "camera" }
        if k.hasPrefix("smart_meter") { return "meter" }
        if k.hasPrefix("pet_") { return "pet" }
        // тип «other» и неизвестные — пробуем угадать по названию
        if nameHas(["лампа", "лампочк", "светильник", "люстра", "торшер", "бра ", "подсветк", "лент", "ночник"]) { return "light" }
        if nameHas(["розетка"]) { return "socket" }
        if nameHas(["выключатель"]) { return "switch" }
        if nameHas(["кондиционер", "обогреват", "радиатор", "конвектор", "тёплый пол", "теплый пол", "увлажнит", "очистител", "вентилятор", "термостат"]) { return "climate" }
        if nameHas(["телевизор", "приставка", "колонка", "станция", "проектор", "ресивер", "саундбар"]) { return "media" }
        if nameHas(["чайник", "кофе", "мульти", "духов", "плита", "холодильник", "хлебопеч", "блендер", "миксер"]) { return "kitchen" }
        if nameHas(["пылесос", "стираль", "посудомо", "утюг", "сушил"]) { return "cleaning" }
        if nameHas(["штор", "жалюзи", "карниз", "ворота", "замок", "дверь", "клапан"]) { return "cover" }
        if nameHas(["датчик"]) { return "sensor" }
        if nameHas(["камера"]) { return "camera" }
        if nameHas(["счётчик", "счетчик"]) { return "meter" }
        if nameHas(["кормушка", "поилка"]) { return "pet" }
        return "other"
    }

    /// значок SF Symbols: берётся первый, который есть в этой версии macOS
    var symbol: String {
        let k = kind
        func sub(_ w: String) -> Bool { return k.contains(w) }
        var c: [String] = []
        // некоторые производители отдают увлажнитель или очиститель как «термостат» — название точнее типа
        if nameHas(["увлажн"]) { return firstSymbol(["humidifier.and.droplets.fill", "humidity.fill", "drop.fill"]) }
        if nameHas(["очистител"]) { return firstSymbol(["air.purifier.fill", "wind"]) }
        if nameHas(["вентилятор"]) { return firstSymbol(["fan.fill", "wind"]) }
        if nameHas(["кондиционер", "сплит"]) { return firstSymbol(["air.conditioner.horizontal.fill", "snowflake"]) }
        if k.hasPrefix("light") {
            if sub("strip") || nameHas(["лент", "подсветк"]) { c = ["lightbulb.led.fill", "lightbulb.fill"] }
            else if sub("ceiling") || nameHas(["люстр", "потолоч"]) { c = ["lamp.ceiling.fill", "lightbulb.fill"] }
            else if nameHas(["торшер"]) { c = ["lamp.floor.fill", "lightbulb.fill"] }
            else if nameHas(["настольн", "ночник"]) { c = ["lamp.table.fill", "lightbulb.fill"] }
            else { c = ["lightbulb.fill"] }
        }
        else if k.hasPrefix("socket") { c = ["powerplug.fill"] }
        else if k.hasPrefix("switch") { c = ["switch.2"] }
        else if k.hasPrefix("thermostat") {
            if sub("ac") || nameHas(["кондиц", "сплит"]) { c = ["air.conditioner.horizontal.fill", "snowflake"] }
            else if nameHas(["обогрев", "радиатор", "конвектор", "тёплый пол", "теплый пол"]) { c = ["heater.vertical.fill", "flame.fill"] }
            else { c = ["thermometer.medium"] }
        }
        else if k.hasPrefix("humidifier") { c = ["humidifier.and.droplets.fill", "humidity.fill"] }
        else if k.hasPrefix("purifier") { c = ["air.purifier.fill", "wind"] }
        else if k.hasPrefix("fan") || k.hasPrefix("ventilation") { c = ["fan.fill", "wind"] }
        else if k.hasPrefix("smart_speaker") { c = ["homepod.fill", "hifispeaker.fill"] }
        else if k.hasPrefix("media_device.tv_box") { c = ["appletv.fill", "tv"] }
        else if k.hasPrefix("media_device.receiver") { c = ["hifispeaker.2.fill", "hifispeaker.fill"] }
        else if k.hasPrefix("media_device.tv") || k.hasPrefix("tv") { c = ["tv.fill"] }
        else if k.hasPrefix("media_device") {
            if nameHas(["проектор"]) { c = ["videoprojector.fill", "play.tv.fill"] } else { c = ["hifispeaker.fill", "play.tv.fill"] }
        }
        else if isKettle { c = ["cup.and.saucer.fill"] }
        else if k.hasPrefix("cooking") {
            if sub("coffee") { c = ["mug.fill", "cup.and.saucer.fill"] }
            else if nameHas(["духов"]) { c = ["oven.fill", "fork.knife"] }
            else if sub("multicooker") { c = ["frying.pan.fill", "fork.knife"] }
            else { c = ["fork.knife"] }
        }
        else if k.hasPrefix("vacuum") { c = ["robotic.vacuum.fill", "sparkles"] }
        else if k.hasPrefix("washing") { c = ["washer.fill"] }
        else if k.hasPrefix("dishwasher") { c = ["dishwasher.fill", "sparkles"] }
        else if k.hasPrefix("iron") { c = ["flame.fill"] }
        else if k.hasPrefix("openable.curtain") { c = ["blinds.horizontal.closed", "window.shade.closed"] }
        else if k.hasPrefix("openable.valve") { c = ["spigot.fill", "drop.fill"] }
        else if k.hasPrefix("openable") {
            if nameHas(["ворот", "гараж"]) { c = ["door.garage.closed", "door.left.hand.closed"] }
            else if nameHas(["замок"]) { c = ["lock.fill"] }
            else if nameHas(["штор", "жалюзи", "карниз"]) { c = ["blinds.horizontal.closed", "window.shade.closed"] }
            else { c = ["door.left.hand.closed", "door.left.hand.open"] }
        }
        else if k.hasPrefix("sensor") {
            if sub("motion") { c = ["figure.walk.motion", "figure.walk"] }
            else if sub("open") { c = ["door.left.hand.open", "rectangle.portrait.on.rectangle.portrait"] }
            else if sub("button") { c = ["button.programmable", "circle.circle.fill"] }
            else if sub("smoke") { c = ["smoke.fill", "flame.fill"] }
            else if sub("gas") { c = ["aqi.medium", "exclamationmark.triangle.fill"] }
            else if sub("vibration") { c = ["waveform.path", "waveform"] }
            else if sub("illumination") { c = ["sun.max.fill"] }
            else if sub("water_leak") { c = ["drop.triangle.fill", "drop.fill"] }
            else if sub("climate") { c = ["thermometer.medium"] }
            else { c = ["sensor.fill", "sensor.tag.radiowaves.forward.fill"] }
        }
        else if k.hasPrefix("camera") { c = ["web.camera.fill", "video.fill"] }
        else if k.hasPrefix("smart_meter") {
            if sub("electricity") { c = ["bolt.fill"] }
            else if sub("gas") { c = ["flame.fill"] }
            else if sub("water") { c = ["drop.fill"] }
            else if sub("heat") { c = ["thermometer.sun.fill", "flame.fill"] }
            else { c = ["gauge.medium", "gauge"] }
        }
        else if k.hasPrefix("pet_feeder") { c = ["pawprint.fill"] }
        else if k.hasPrefix("pet_drinking") { c = ["drop.fill", "pawprint.fill"] }
        else if k.hasPrefix("hub") { c = ["wifi.router.fill", "dot.radiowaves.left.and.right"] }
        else {
            // «other»: смотрим на название, а не на тип
            switch cat {
            case "light": c = ["lightbulb.fill"]
            case "socket": c = ["powerplug.fill"]
            case "switch": c = ["switch.2"]
            case "climate": c = ["thermometer.medium"]
            case "media": c = ["tv.fill", "hifispeaker.fill"]
            case "kitchen": c = ["fork.knife"]
            case "cleaning": c = ["sparkles"]
            case "cover": c = ["door.left.hand.closed"]
            case "sensor": c = ["sensor.fill", "sensor.tag.radiowaves.forward.fill"]
            case "camera": c = ["web.camera.fill", "video.fill"]
            case "meter": c = ["gauge.medium", "gauge"]
            case "pet": c = ["pawprint.fill"]
            default: c = []
            }
        }
        return firstSymbol(c)
    }

    /// картинка устройства: сначала по названию (как в приложении на iPhone), потом по типу
    var iconKey: String? {
        let n = name.lowercased()
        let k = kind
        let padded = " " + n + " "
        func has(_ s: String) -> Bool { return n.contains(s) }
        func kk(_ s: String) -> Bool { return k.contains(s) }
        func hasAny(_ ws: [String]) -> Bool { for w in ws where n.contains(w) { return true }; return false }
        if has("пульт") { return "ir" }
        if has("выключат") { return "switch2" }
        if has("гуви") || has("настольн") { return "lamp_white" }
        if has("кубик") || has("ночник") { return "lamp_pink" }
        if has("эмби") { return "lamp_ambi" }
        if has("кондиц") || has("сплит") || kk("thermostat.ac") { return "ac" }
        if has("очист") || k.hasPrefix("purifier") { return "purifier" }
        if has("увлажн") || k.hasPrefix("humidifier") { return "humidifier" }
        if has("робик") || has("пылесос") || k.hasPrefix("vacuum") { return "vacuum" }
        if has("чайник") || kk("kettle") { return "kettle" }
        if has("музык") { return "music" }
        if has("подсветка т") || has("лент") || has("подсветка тв") || kk("light.strip") { return "strip" }

        // умные колонки: размер и форма зависят от модели
        let spk = k.hasPrefix("smart_speaker") || has("станци") || has("колонк") || has("алис")
        if spk {
            if has("макс") || has("max") { return "max" }
            if has("лайт") || has("lite") { return "lite" }
            if has("миди") || has("midi") { return "midi" }
            if has("мини") || has("mini") { return "mini" }
            if has("стрит") {
                let sc = id.unicodeScalars.reduce(0) { $0 + Int($1.value) }
                return sc % 2 == 0 ? "street_gray" : "street_black"
            }
            return "station"
        }

        // телевизоры и медиа
        if kk("tv_box") || has("приставк") { return "tvbox" }
        if has("проектор") { return "projector" }
        if kk("receiver") || hasAny(["саундбар", "ресивер", "soundbar"]) { return "soundbar" }
        if padded.contains(" тв") || has("телев") || has("tv") || k.hasPrefix("media_device.tv") || k.hasPrefix("tv") { return "tv" }
        if k.hasPrefix("media_device") { return "soundbar" }

        // датчики
        if k.hasPrefix("sensor") {
            if kk("motion") || has("движен") { return "s_motion" }
            if kk("open") || hasAny(["открыт", "двер", "окн"]) { return "s_door" }
            if kk("button") || has("кнопк") { return "s_button" }
            if kk("smoke") || has("дым") { return "s_smoke" }
            if kk("gas") || has("газ") { return "s_gas" }
            if kk("vibration") || has("вибрац") { return "s_vib" }
            if kk("illumination") || has("освещ") { return "s_light" }
            if kk("water_leak") || has("протеч") { return "s_leak" }
            if kk("climate") || hasAny(["температур", "влажн", "климат"]) { return "s_climate" }
            return "s_generic"
        }
        // счётчики
        if k.hasPrefix("smart_meter") {
            if kk("electricity") { return "m_elec" }
            if kk("gas") { return "m_gas" }
            if kk("water") { return "m_water" }
            if kk("heat") { return "m_heat" }
            return "m_generic"
        }
        if k.hasPrefix("camera") || has("камер") { return "camera" }
        if k.hasPrefix("pet_feeder") || has("кормуш") { return "pet_feeder" }
        if k.hasPrefix("pet_drinking") || hasAny(["поилк", "фонтан"]) { return "pet_fountain" }
        if k.hasPrefix("hub") || hasAny(["хаб", "шлюз"]) { return "hub" }

        // шторы, ворота, замки
        if k.hasPrefix("openable") {
            if kk("valve") || hasAny(["клапан", "кран"]) { return "valve" }
            if hasAny(["ворот", "гараж"]) { return "gate" }
            if has("замок") { return "lock" }
            return "curtain"
        }
        if hasAny(["штор", "жалюзи", "карниз"]) { return "curtain" }
        if hasAny(["ворот", "гараж"]) { return "gate" }
        if has("замок") { return "lock" }

        // кухня и бытовая техника
        if kk("coffee") || has("кофе") { return "coffee" }
        if kk("multicooker") || has("мультивар") { return "multicooker" }
        if has("холодил") { return "fridge" }
        if hasAny(["духов", "плита", "варочн"]) { return "oven" }
        if k.hasPrefix("cooking") { return "multicooker" }
        if k.hasPrefix("washing") || has("стираль") { return "washer" }
        if k.hasPrefix("dishwasher") || has("посудомо") { return "dishwasher" }
        if k.hasPrefix("iron") || has("утюг") { return "iron" }

        // климат
        if k.hasPrefix("fan") || k.hasPrefix("ventilation") || has("вентилятор") { return "fan" }
        if hasAny(["обогрев", "радиатор", "конвектор", "тёплый пол", "теплый пол"]) || k.hasPrefix("thermostat") { return "heater" }

        // свет и розетки
        if has("розетк") || k.hasPrefix("socket") { return "socket" }
        if hasAny(["потолоч", "люстр", "плафон"]) || kk("light.ceiling") { return "ceiling" }
        if has("торшер") { return "floorlamp" }
        if has("ламп") || has("подсвет") || has("включ") || k.hasPrefix("light") || has("светильник") {
            if let c = color, !c.model.isEmpty, !has("лампоч"), !has("подсвет") { return "lamp_pink" }
            return "bulb"
        }
        if k.hasPrefix("switch") { return "switch2" }
        return nil
    }

    var sub: String {
        if !online { return "Не в сети" }
        if let s = statusLine, isKettle || isProcess { return s }
        var out: [String] = []
        if cat == "climate", on == true {
            if let m = modes.first(where: { $0.instance == "thermostat" }), !m.value.isEmpty { out.append(modeValueTitle(m.value)) }
            if let t = target { out.append(Dev.num(t.value) + "°") }
        }
        if cat == "light", on == true, let b = bright { out.append(String(Int(b.value.rounded())) + "%") }
        for p in props {
            switch p.instance {
            case "temperature": out.append(Dev.num(p.value) + "°")
            case "humidity": out.append(String(Int(p.value.rounded())) + "%")
            case "battery_level": out.append("заряд " + String(Int(p.value.rounded())) + "%")
            case "power": out.append(String(Int(p.value.rounded())) + " Вт")
            case "co2_level": out.append("CO₂ " + String(Int(p.value.rounded())))
            default: break
            }
        }
        return out.prefix(3).joined(separator: " · ")
    }

    static func num(_ v: Double) -> String {
        let s = String(format: "%.1f", v)
        return s.replacingOccurrences(of: ".0", with: "").replacingOccurrences(of: ".", with: ",")
    }
}

var symbolOK: [String: Bool] = [:]

/// первый значок из списка, который существует в этой версии macOS (новые значки на старых системах не рисуются)
func firstSymbol(_ names: [String]) -> String {
    for n in names {
        if let ok = symbolOK[n] { if ok { return n } else { continue } }
        let ok = NSImage(systemSymbolName: n, accessibilityDescription: nil) != nil
        symbolOK[n] = ok
        if ok { return n }
    }
    return "circle.grid.2x2.fill"
}

struct Room: Identifiable {
    var hh: String = ""
    var id: String
    var name: String
    var devices: [Dev]
}

struct Household: Identifiable {
    var id: String
    var name: String
}

struct Scen: Identifiable {
    var id: String
    var name: String
}

func byName(_ a: String, _ b: String) -> Bool {
    return a.localizedStandardCompare(b) == .orderedAscending
}

// MARK: - Подписи (по-русски)

func modeTitle(_ i: String) -> String {
    switch i {
    case "thermostat": return "Режим"
    case "fan_speed": return "Скорость вентилятора"
    case "swing": return "Направление воздуха"
    case "program": return "Программа"
    case "cleanup_mode": return "Режим уборки"
    case "work_speed": return "Скорость работы"
    case "tea_mode": return "Чай"
    case "coffee_mode": return "Кофе"
    case "dishwashing": return "Мойка"
    case "input_source": return "Источник"
    case "heat": return "Нагрев"
    default: return i
    }
}

func modeValueTitle(_ v: String) -> String {
    switch v {
    case "heat": return "Обогрев"
    case "cool": return "Холод"
    case "auto": return "Авто"
    case "eco": return "Эко"
    case "dry": return "Осушение"
    case "fan_only": return "Вентиляция"
    case "turbo": return "Турбо"
    case "quiet": return "Тихо"
    case "low": return "Низкая"
    case "medium": return "Средняя"
    case "high": return "Высокая"
    case "max": return "Макс"
    case "min": return "Мин"
    case "normal": return "Обычный"
    case "fast": return "Быстро"
    case "slow": return "Медленно"
    case "horizontal": return "Горизонт."
    case "vertical": return "Вертик."
    case "stationary": return "Фикс."
    case "black_tea": return "Чёрный"
    case "green_tea": return "Зелёный"
    case "white_tea": return "Белый"
    case "oolong_tea": return "Улун"
    case "puerh_tea": return "Пуэр"
    case "herbal_tea": return "Травяной"
    case "flower_tea": return "Цветочный"
    case "red_tea": return "Красный"
    case "espresso": return "Эспрессо"
    case "americano": return "Американо"
    case "cappuccino": return "Капучино"
    case "latte": return "Латте"
    case "one": return "1"
    case "two": return "2"
    case "three": return "3"
    case "four": return "4"
    case "five": return "5"
    case "six": return "6"
    case "seven": return "7"
    case "eight": return "8"
    case "nine": return "9"
    case "ten": return "10"
    case "smart_cleaning": return "Умная"
    case "spot_cleaning": return "Точечная"
    case "wet_cleaning": return "Влажная"
    case "dry_cleaning": return "Сухая"
    default:
        let s = v.replacingOccurrences(of: "_", with: " ")
        return s.prefix(1).uppercased() + s.dropFirst()
    }
}

func modeValueSymbol(_ v: String) -> String? {
    switch v {
    case "heat": return "sun.max.fill"
    case "cool": return "snowflake"
    case "auto": return "a.circle.fill"
    case "eco": return "leaf.fill"
    case "dry": return "drop.fill"
    case "fan_only": return "wind"
    case "turbo": return "bolt.fill"
    case "quiet": return "moon.fill"
    default: return nil
    }
}

func toggleTitle(_ i: String) -> String {
    switch i {
    case "mute": return "Без звука"
    case "pause": return "Пауза"
    case "oscillation": return "Качание"
    case "keep_warm": return "Поддерживать тепло"
    case "backlight": return "Подсветка"
    case "controls_locked": return "Блокировка кнопок"
    case "ionization": return "Ионизация"
    default: return i
    }
}

func toggleSymbol(_ i: String) -> String {
    switch i {
    case "mute": return "speaker.slash.fill"
    case "pause": return "pause.fill"
    case "oscillation": return "arrow.left.and.right"
    case "keep_warm": return "flame.fill"
    case "backlight": return "light.max"
    case "controls_locked": return "lock.fill"
    case "ionization": return "sparkles"
    default: return "switch.2"
    }
}

func sceneTitle(_ i: String) -> String {
    switch i {
    case "alarm": return "Тревога"
    case "alice": return "Алиса"
    case "candle": return "Свеча"
    case "dinner": return "Ужин"
    case "lights_off": return "Свет выкл."
    case "fantasy": return "Фантазия"
    case "garland": return "Гирлянда"
    case "jungle": return "Джунгли"
    case "movie": return "Кино"
    case "neon": return "Неон"
    case "night": return "Ночь"
    case "ocean": return "Океан"
    case "party": return "Вечеринка"
    case "reading": return "Чтение"
    case "rest": return "Отдых"
    case "romance": return "Романтика"
    case "siren": return "Сирена"
    case "sunrise": return "Рассвет"
    case "sunset": return "Закат"
    case "work": return "Работа"
    case "energy": return "Энергия"
    case "leisure": return "Досуг"
    case "soft": return "Мягкий"
    case "lava_lamp": return "Лава-лампа"
    case "northern", "northern_lights", "aurora": return "Северное сияние"
    case "fire", "fireplace": return "Огонь"
    case "rainbow": return "Радуга"
    case "breath", "breathing": return "Дыхание"
    case "pulse": return "Пульс"
    case "pendulum": return "Маятник"
    case "summer": return "Лето"
    case "autumn": return "Осень"
    case "spring": return "Весна"
    case "winter": return "Зима"
    case "christmas_tree": return "Ёлка"
    case "christmas": return "Рождество"
    case "new_year": return "Новый год"
    case "miracle": return "Чудо"
    case "fairy_lights", "fairy": return "Сказочные огни"
    case "evening": return "Вечер"
    case "game", "gaming": return "Игра"
    case "circadian": return "Циркадный"
    case "meditation": return "Медитация"
    case "relax": return "Расслабление"
    case "focus": return "Фокус"
    case "disco": return "Дискотека"
    case "storm", "thunderstorm": return "Гроза"
    case "rain": return "Дождь"
    case "space", "cosmos": return "Космос"
    case "sea": return "Море"
    case "forest": return "Лес"
    case "love": return "Любовь"
    case "sakura": return "Сакура"
    case "sunny", "sun": return "Солнце"
    case "flame": return "Пламя"
    case "dawn": return "Рассвет"
    case "dusk": return "Сумерки"
    case "halloween": return "Хэллоуин"
    case "valentine": return "День влюблённых"
    case "birthday": return "День рождения"
    case "inactive": return "Выключена"
    default:
        let t = modeValueTitle(i)
        // латиницу не показываем — пишем по-русски
        return t.range(of: "[A-Za-z]", options: .regularExpression) != nil ? "Особый режим" : t
    }
}

/// как сцена выглядит вживую (по описаниям Яндекса и поведению ламп): основной цвет — первый
func sceneColors(_ i: String) -> [Color] {
    func c(_ hex: Int) -> Color {
        return Color(red: Double((hex >> 16) & 255) / 255, green: Double((hex >> 8) & 255) / 255, blue: Double(hex & 255) / 255)
    }
    switch i {
    case "candle": return [c(0xFF9A3C), c(0xFFB860), c(0xFF7F2A)]          // тёплое мерцание
    case "night": return [c(0xE0823F), c(0xB8602E)]                         // тусклый тёплый ночник
    case "rest": return [c(0xFFC98A), c(0xFFB27A)]                          // мягкий тёплый
    case "dinner": return [c(0xFFD9A8), c(0xFFC890)]                        // тёплый белый
    case "reading": return [c(0xF3F7FF), c(0xFFF6E8)]                       // яркий нейтральный белый
    case "work": return [c(0xEAF2FF), c(0xFFFFFF)]
    case "sunrise": return [c(0xFFB46A), c(0xFF7A45), c(0xFFE7C2)]          // от красно-оранжевого к тёплому белому
    case "sunset": return [c(0xFF8A4C), c(0xE8576B), c(0x8A4FB5)]           // тёплый → оранжево-красный → гаснет
    case "romance": return [c(0xF0508A), c(0xC2408F)]                       // розово-малиновый, мягкий
    case "movie": return [c(0x4B5BC9), c(0x6A4FC7)]                         // приглушённый сине-фиолетовый
    case "ocean": return [c(0x2F8CF0), c(0x22C3D6), c(0x3A6FE0)]            // сине-бирюзовые волны
    case "jungle": return [c(0x36B35A), c(0x9BD64A), c(0x1F8F5F)]           // зелёные переливы
    case "neon": return [c(0xF03CD4), c(0x34D6F5)]                          // розовый и бирюзовый
    case "fantasy": return [c(0xF59AD8), c(0xA98BFF), c(0x8CCBFF)]          // пастельные переливы
    case "alice": return [c(0x8A5CFF), c(0x5B7CFF), c(0xC05CFF)]            // фиолетовые переливы Алисы
    case "party": return [c(0xFF4D6D), c(0xFFC93C), c(0x3DDC84), c(0x4D8DFF), c(0xB45CFF)]
    case "garland": return [c(0xFF4040), c(0x3DDC84), c(0xFFC93C), c(0x4D8DFF)]
    case "siren": return [c(0xFF3030), c(0x3050FF)]                         // красный ↔ синий
    case "alarm": return [c(0xFF2D2D), c(0xB01515)]                         // красные вспышки
    case "lava_lamp": return [c(0xFF6A3D), c(0xE0457B), c(0xA24DFF)]
    case "northern", "northern_lights", "aurora": return [c(0x2EE89A), c(0x1FB5C9), c(0x7A4DFF)]
    case "fire", "fireplace", "flame": return [c(0xFF5A1F), c(0xFF9A1F), c(0xFFD23C)]
    case "rainbow": return [c(0xFF3B3B), c(0xFFB020), c(0xFFF04A), c(0x3DDC84), c(0x3D8BFF), c(0x9B4DFF)]
    case "breath", "breathing": return [c(0x9D7BFF), c(0xD6B8FF)]
    case "pulse": return [c(0xFF3D7F), c(0xFF8AB5)]
    case "pendulum": return [c(0x3D7BFF), c(0xFF5CA8)]
    case "summer": return [c(0xFFD23C), c(0x7EDB4A), c(0x3DC4FF)]
    case "autumn": return [c(0xFF7A1F), c(0xC2471A), c(0xFFB43C)]
    case "spring": return [c(0x8FE07A), c(0xFF9AC8)]
    case "winter": return [c(0x9BD8FF), c(0xE8F6FF), c(0x5FA8FF)]
    case "christmas_tree": return [c(0x1F9D4C), c(0xFF3B3B), c(0xFFC93C)]
    case "christmas": return [c(0xE53935), c(0x2E9E4F)]
    case "new_year": return [c(0xFFD23C), c(0xE53935), c(0x3D7BFF)]
    case "miracle": return [c(0xFFD36B), c(0xFFF2C6), c(0x8FB8FF)]
    case "fairy_lights", "fairy": return [c(0xFFC75A), c(0xFFE7A3)]
    case "evening": return [c(0xFFA94D), c(0xFF8A3D)]
    case "game", "gaming": return [c(0xFF2ED1), c(0x2EE6FF), c(0x7A4DFF)]
    case "circadian": return [c(0xFFC07A), c(0xF2F6FF)]
    case "meditation": return [c(0x3DC9B0), c(0x7A8CFF)]
    case "relax": return [c(0xFFB27A), c(0xC98BFF)]
    case "focus": return [c(0xEAF2FF), c(0xBFD8FF)]
    case "disco": return [c(0xFF3BC8), c(0x3DDCFF), c(0xFFE03D)]
    case "storm", "thunderstorm": return [c(0x3A3F8F), c(0xB8C8FF), c(0x6A4FC7)]
    case "rain": return [c(0x5A8FD6), c(0x9FC3E8)]
    case "space", "cosmos": return [c(0x2B1F6B), c(0x8A4DFF), c(0x1FA3C9)]
    case "sea": return [c(0x1E88E5), c(0x00C2C7)]
    case "forest": return [c(0x2E8B57), c(0x7CC24A)]
    case "love", "valentine": return [c(0xFF3D6E), c(0xFF8AB5)]
    case "sakura": return [c(0xFFB3D1), c(0xFF7FB0)]
    case "sunny", "sun": return [c(0xFFC93C), c(0xFFE58A)]
    case "dusk": return [c(0x8A4FB5), c(0xFF8A4C)]
    case "halloween": return [c(0xFF7A1F), c(0x7A2FB5)]
    case "birthday": return [c(0xFF5C8A), c(0xFFC93C), c(0x5CC8FF)]
    case "inactive": return [c(0xB8BBC2), c(0xD4D6DB)]
    default: return [c(0xA08CFF), c(0xF0A0D8)]
    }
}

/// как сцена ведёт себя вживую
func sceneHint(_ i: String) -> String {
    switch i {
    case "candle": return "тёплое мерцание"
    case "night": return "тусклый тёплый"
    case "rest": return "мягкий тёплый"
    case "dinner": return "тёплый белый"
    case "reading": return "яркий белый"
    case "work": return "холодный белый"
    case "sunrise": return "плавно светлеет"
    case "sunset": return "плавно гаснет"
    case "romance": return "розовый, приглушённый"
    case "movie": return "приглушённый синий"
    case "ocean": return "сине-бирюзовые волны"
    case "jungle": return "зелёные переливы"
    case "neon": return "розовый и бирюзовый"
    case "fantasy": return "пастельные переливы"
    case "alice": return "фиолетовые переливы"
    case "party": return "быстрая радуга"
    case "garland": return "мигает цветами"
    case "siren": return "красный ↔ синий"
    case "alarm": return "красные вспышки"
    case "lava_lamp": return "медленные переливы"
    case "inactive": return "без подсветки"
    case "northern", "northern_lights", "aurora": return "зелёно-фиолетовые волны"
    case "fire", "fireplace", "flame": return "живое пламя"
    case "rainbow": return "плавная радуга"
    case "breath", "breathing": return "мягко «дышит»"
    case "pulse": return "ритмичные вспышки"
    case "pendulum": return "цвета качаются"
    case "summer": return "солнечный, яркий"
    case "autumn": return "оранжево-медный"
    case "spring": return "свежий пастельный"
    case "winter": return "холодный голубой"
    case "christmas_tree": return "зелёный с огоньками"
    case "christmas": return "красный и зелёный"
    case "new_year": return "праздничные огни"
    case "miracle": return "золотые искры"
    case "fairy_lights", "fairy": return "тёплые мерцающие огни"
    case "evening": return "тёплый вечерний"
    case "game", "gaming": return "яркие неоновые"
    case "circadian": return "меняется за день"
    case "meditation": return "спокойный бирюзовый"
    case "relax": return "мягкий тёплый"
    case "focus": return "холодный белый"
    case "disco": return "быстрая смена цветов"
    case "storm", "thunderstorm": return "вспышки молний"
    case "rain": return "спокойный синий"
    case "space", "cosmos": return "глубокий фиолетовый"
    case "sea": return "сине-бирюзовый"
    case "forest": return "зелёный"
    case "love", "valentine": return "розовый"
    case "sakura": return "нежно-розовый"
    case "sunny", "sun": return "солнечный жёлтый"
    case "dusk": return "фиолетово-оранжевый"
    default: return ""
    }
}

/// сцены, которые меняют цвет — их «шарик» медленно переливается
func sceneMoves(_ i: String) -> Bool {
    return ["ocean", "jungle", "neon", "fantasy", "alice", "party", "garland", "siren", "alarm", "lava_lamp", "candle", "sunrise", "sunset",
            "northern", "northern_lights", "aurora", "fire", "fireplace", "flame", "rainbow", "breath", "breathing", "pulse", "pendulum",
            "christmas_tree", "christmas", "new_year", "miracle", "fairy_lights", "fairy", "game", "gaming", "disco", "storm", "thunderstorm", "space", "cosmos"].contains(i)
}

func sceneSymbol(_ i: String) -> String {
    switch i {
    case "candle": return "flame.fill"
    case "lava_lamp": return "drop.fill"
    case "inactive": return "power"
    case "sunset": return "sun.haze.fill"
    case "sunrise": return "sunrise.fill"
    case "ocean": return "water.waves"
    case "jungle": return "leaf.fill"
    case "neon": return "bolt.fill"
    case "party": return "music.note"
    case "romance": return "heart.fill"
    case "movie": return "film.fill"
    case "night": return "moon.stars.fill"
    case "reading": return "book.fill"
    case "work": return "laptopcomputer"
    case "alarm": return "exclamationmark.triangle.fill"
    case "siren": return "bell.fill"
    case "alice": return "waveform"
    case "fantasy": return "wand.and.stars"
    case "garland": return "sparkles"
    case "dinner": return "fork.knife"
    case "rest": return "cup.and.saucer.fill"
    default: return "sparkles"
    }
}

/// светлые сцены — тёмная подпись
func sceneLight(_ i: String) -> Bool {
    return i == "reading" || i == "work" || i == "dinner"
}

/// у станций «Выключена» — первой
func stationOrder(_ s: [String], _ station: Bool) -> [String] {
    guard station, s.contains("inactive") else { return s }
    return ["inactive"] + s.filter { $0 != "inactive" }
}

func rangeTitle(_ d: Dev, _ i: String) -> String {
    switch i {
    case "brightness": return "Яркость"
    case "temperature": return d.isKettle ? "Температура воды" : (d.cat == "climate" ? "Температура" : "Температура")
    case "humidity": return "Влажность"
    case "volume": return "Громкость"
    case "channel": return "Канал"
    case "open": return "Открыто"
    default: return i
    }
}

func rangeSymbol(_ i: String) -> String {
    switch i {
    case "brightness": return "sun.max.fill"
    case "temperature": return "thermometer.medium"
    case "humidity": return "humidity.fill"
    case "volume": return "speaker.wave.2.fill"
    case "channel": return "tv"
    case "open": return "arrow.up.and.down"
    default: return "slider.horizontal.3"
    }
}

func propTitle(_ i: String) -> String {
    switch i {
    case "temperature": return "Температура"
    case "humidity": return "Влажность"
    case "pressure": return "Давление"
    case "battery_level": return "Заряд"
    case "power": return "Мощность"
    case "voltage": return "Напряжение"
    case "amperage": return "Ток"
    case "co2_level": return "CO₂"
    case "illumination": return "Освещённость"
    case "water_level": return "Уровень воды"
    case "pm2.5_density": return "PM2.5"
    default: return i
    }
}

func propValue(_ p: Prop) -> String {
    let n = Dev.num(p.value)
    switch p.instance {
    case "temperature": return n + "°"
    case "humidity", "battery_level", "water_level": return n + "%"
    case "power": return n + " Вт"
    case "voltage": return n + " В"
    case "amperage": return n + " А"
    case "illumination": return n + " лк"
    default: return n
    }
}

// MARK: - Иконки устройств: см. Icons.swift (вынесены, чтобы не хранить в репозитории чужую графику)

var iconCache: [String: NSImage] = [:]

func loadIcon(_ key: String) -> NSImage? {
    if let c = iconCache[key] { return c }
    guard let b = Icons.iconData[key], let data = Data(base64Encoded: b), let im = NSImage(data: data) else { return nil }
    iconCache[key] = im
    return im
}

// MARK: - Настройки

let ud = UserDefaults.standard

func udBool(_ k: String, _ def: Bool) -> Bool {
    return (ud.object(forKey: k) as? Bool) ?? def
}

// MARK: - Модель данных и обращение к API

final class HomeModel: ObservableObject {
    @Published var token: String? = Keychain.get()
    @Published var rooms: [Room] = []
    @Published var scenarios: [Scen] = []
    @Published var loading = false
    @Published var error: String?
    @Published var toast: String?
    @Published var ranScenario: String?
    @Published var waiting = false
    @Published var manual = ""
    @Published var showManual = false
    @Published var draft: [String: Double] = [:]
    @Published var households: [Household] = []
    @Published var hh: String = ud.string(forKey: "hh") ?? ""
    @Published var filter: String? = nil
    @Published var tab = 0
    @Published var detailID: String? = nil
    @Published var quickID: String? = nil { didSet { if quickID != oldValue { startQuickWatch() } } }
    weak var mainWindow: NSWindow?
    var quickTimer: Timer?
    var awaySince: Date?
    @Published var showSettings = false
    @Published var hover: String? = nil
    @Published var colorOpen: Set<String> = []
    @Published var heights: [String: CGFloat] = [:]

    func setHeight(_ k: String, _ v: CGFloat) {
        if abs((heights[k] ?? 0) - v) > 1 { heights[k] = v }
    }
    @Published var hoverRoom: String? = nil
    @Published var draggingRoom: String? = nil
    @Published var collapsed: Set<String> = []
    @Published var doneMsg: String? = nil

    // настройки виджета
    @Published var barMode: String = ud.string(forKey: "barMode") ?? "count" { didSet { ud.set(barMode, forKey: "barMode"); notifyStatus() } }
    @Published var barDevice: String = ud.string(forKey: "barDevice") ?? "" { didSet { ud.set(barDevice, forKey: "barDevice"); notifyStatus() } }
    @Published var barItems: [String] = HomeModel.loadBar() { didSet { ud.set(barItems, forKey: "barItems"); notifyStatus() } }
    @Published var barBusy: Bool = udBool("barBusy", true) { didSet { ud.set(barBusy, forKey: "barBusy"); notifyStatus() } }
    @Published var hoverOpen: Bool = udBool("hoverOpen", true) { didSet { ud.set(hoverOpen, forKey: "hoverOpen") } }
    @Published var hoverTiles: Bool = udBool("hoverTiles", true) { didSet { ud.set(hoverTiles, forKey: "hoverTiles") } }
    @Published var doneSound: Bool = udBool("doneSound", true) { didSet { ud.set(doneSound, forKey: "doneSound") } }
    @Published var showOffline: Bool = udBool("showOffline", true) { didSet { ud.set(showOffline, forKey: "showOffline") } }

    var badCaps: Set<String> = Set((ud.array(forKey: "badCaps") as? [String]) ?? []) { didSet { ud.set(Array(badCaps), forKey: "badCaps") } }
    @Published var favs: [String] = (ud.array(forKey: "favs") as? [String]) ?? [] { didSet { ud.set(favs, forKey: "favs") } }
    @Published var roomOrder: [String] = (ud.array(forKey: "roomOrder") as? [String]) ?? [] { didSet { ud.set(roomOrder, forKey: "roomOrder") } }

    let server = AuthServer()
    var timer: Timer?
    var isOpen = false

    // проверка обновлений
    @Published var latestTag: String? = ud.string(forKey: "latestTag") { didSet { ud.set(latestTag, forKey: "latestTag") } }
    @Published var latestURL: String? = ud.string(forKey: "latestURL") { didSet { ud.set(latestURL, forKey: "latestURL") } }
    @Published var latestNotes: [String] = (ud.array(forKey: "latestNotes") as? [String]) ?? [] { didSet { ud.set(latestNotes, forKey: "latestNotes") } }
    @Published var dismissedTag: String = ud.string(forKey: "dismissedTag") ?? "" { didSet { ud.set(dismissedTag, forKey: "dismissedTag"); notifyStatus() } }

    /// баннер «что нового» показываем, пока версию не скрыли
    var showUpdateBanner: Bool { return updateAvailable && dismissedTag != (latestTag ?? "") }

    /// описание релиза с GitHub → короткий список (без заголовков и блока про установку)
    static func parseNotes(_ body: String) -> [String] {
        var out: [String] = []
        for raw in body.replacingOccurrences(of: "\r", with: "").components(separatedBy: "\n") {
            var l = raw.trimmingCharacters(in: .whitespaces)
            if l.isEmpty { continue }
            if l.hasPrefix("#") {
                let h = l.drop { $0 == "#" || $0 == " " }.lowercased()
                if h.contains("установ") || h.contains("install") { break }
                continue
            }
            if l.hasPrefix("- ") || l.hasPrefix("* ") || l.hasPrefix("• ") { l = String(l.dropFirst(2)) }
            else if l.hasPrefix("-") || l.hasPrefix("*") { l = String(l.dropFirst(1)).trimmingCharacters(in: .whitespaces) }
            l = l.replacingOccurrences(of: "**", with: "").replacingOccurrences(of: "`", with: "")
            // [текст](ссылка) → текст
            while let a = l.range(of: "]("), let o = l[..<a.lowerBound].lastIndex(of: "["), let c = l[a.upperBound...].firstIndex(of: ")") {
                let txt = String(l[l.index(after: o)..<a.lowerBound])
                l.replaceSubrange(o...c, with: txt)
            }
            l = l.trimmingCharacters(in: .whitespaces)
            if !l.isEmpty { out.append(l) }
            if out.count >= 8 { break }
        }
        return out
    }
    @Published var checkingUpdate = false
    @Published var updateMsg: String? = nil
    @Published var autoUpdateCheck: Bool = udBool("autoUpdateCheck", true) { didSet { ud.set(autoUpdateCheck, forKey: "autoUpdateCheck") } }
    @Published var lastUpdateCheck: Date? = ud.object(forKey: "lastUpdateCheck") as? Date

    static func versionParts(_ v: String) -> [Int] {
        var t = v.trimmingCharacters(in: .whitespaces)
        if t.lowercased().hasPrefix("v") { t.removeFirst() }
        return t.split(separator: ".").map { Int($0.prefix { $0.isNumber }) ?? 0 }
    }

    static func agoText(_ d: Date) -> String {
        let sec = Int(Date().timeIntervalSince(d))
        if sec < 60 { return "только что" }
        if sec < 3600 { return "\(sec / 60) мин назад" }
        if sec < 86400 { return "\(sec / 3600) ч назад" }
        return "\(sec / 86400) дн назад"
    }

    static func isNewer(_ a: String, than b: String) -> Bool {
        let x = versionParts(a), y = versionParts(b)
        for i in 0..<max(x.count, y.count) {
            let p = i < x.count ? x[i] : 0, q = i < y.count ? y[i] : 0
            if p != q { return p > q }
        }
        return false
    }

    var updateAvailable: Bool {
        guard let t = latestTag else { return false }
        return HomeModel.isNewer(t, than: appVersion)
    }

    /// спрашиваем у GitHub последний релиз (ничего не устанавливаем)
    func checkUpdate(manual: Bool) {
        if checkingUpdate { return }
        checkingUpdate = true
        if manual { updateMsg = nil }
        guard let url = URL(string: "https://api.github.com/repos/Lenar111/yahome/releases/latest") else { checkingUpdate = false; return }
        var req = URLRequest(url: url)
        req.timeoutInterval = 15
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("MoyDom/" + appVersion, forHTTPHeaderField: "User-Agent")
        URLSession.shared.dataTask(with: req) { [weak self] data, resp, _ in
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            var json: [String: Any]?
            if let d = data { json = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] }
            DispatchQueue.main.async {
                guard let s = self else { return }
                s.checkingUpdate = false
                if code == 200, let j = json, let tag = j["tag_name"] as? String {
                    s.latestTag = tag
                    s.latestURL = (j["html_url"] as? String) ?? "https://github.com/Lenar111/yahome/releases/latest"
                    s.latestNotes = HomeModel.parseNotes((j["body"] as? String) ?? "")
                    s.notifyStatus()
                    s.lastUpdateCheck = Date()
                    ud.set(s.lastUpdateCheck, forKey: "lastUpdateCheck")
                    if manual { s.updateMsg = s.updateAvailable ? nil : "У вас последняя версия" }
                } else if manual {
                    s.updateMsg = code == 0 ? "Нет связи с GitHub" : (code == 404 ? "Релизов пока нет" : "Не получилось проверить (\(code))")
                }
            }
        }.resume()
    }

    /// раз в сутки, без вопросов и установки
    func autoCheckUpdateIfNeeded() {
        guard autoUpdateCheck else { return }
        if let l = lastUpdateCheck, Date().timeIntervalSince(l) < 24 * 3600 { return }
        checkUpdate(manual: false)
    }

    // проверка «включено»: список /user/info у Яндекса бывает устаревшим
    var lastVerify = Date.distantPast
    func verifyOn() {
        guard token != nil, Date().timeIntervalSince(lastVerify) > 20 else { return }
        lastVerify = Date()
        let ids = allDevices.filter { $0.on == true && $0.online && !$0.isKettle && !$0.isProcess }.map { $0.id }.prefix(12)
        for (i, id) in ids.enumerated() {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25 * Double(i)) { [weak self] in self?.pollDevice(id) }
        }
    }
    var heatingIDs: Set<String> = []
    var pending: [String: (Date, (inout Dev) -> Void)] = [:]
    var openWork: DispatchWorkItem?
    var closeWork: DispatchWorkItem?
    var onStatus: (() -> Void)?

    init() {
        server.onToken = { [weak self] t in self?.accept(t) }
        server.onFail = { [weak self] msg in
            self?.waiting = false
            self?.error = msg
        }
        loadHistory()
    }

    // MARK: история показаний датчиков (копится, пока работает виджет)

    @Published var history: [String: [[Double]]] = [:]
    @Published var statsPeriod = 0   // 0 — сутки, 1 — неделя, 2 — месяц, 3 — год, 4 — свой период
    @Published var statsAnchor: Date? = nil   // nil — «сейчас» (скользящее окно), иначе выбранный день
    @Published var customFrom = Date().addingTimeInterval(-7 * 86400)
    @Published var customTo = Date()
    @Published var showPicker = false
    @Published var calMonth = Date()
    @Published var pickMode = 0          // 0 — один день, 1 — период
    @Published var rangeStart: Date? = nil
    var lastCompact = 0.0

    /// начало накопленной истории
    var historyStart: Double {
        var m = Double.greatestFiniteMagnitude
        for (_, a) in history { if let f = a.first { m = Swift.min(m, f[0]) } }
        return m == Double.greatestFiniteMagnitude ? Date().timeIntervalSince1970 : m
    }

    /// окно статистики: (от, до, «сейчас»)
    func statsWindow() -> (Double, Double, Bool) {
        let cal = Calendar.current
        let nowT = Date().timeIntervalSince1970
        if statsPeriod == 4 {
            let a = cal.startOfDay(for: Swift.min(customFrom, customTo))
            let b = cal.date(byAdding: .day, value: 1, to: cal.startOfDay(for: Swift.max(customFrom, customTo))) ?? Date()
            return (a.timeIntervalSince1970, b.timeIntervalSince1970, false)
        }
        guard let a = statsAnchor else {
            let spans: [Double] = [86400.0, 7.0 * 86400.0, 30.0 * 86400.0, 365.0 * 86400.0]
            let span: Double = spans[Swift.min(3, statsPeriod)]
            return (nowT - span, nowT, true)
        }
        switch statsPeriod {
        case 0:
            let st = cal.startOfDay(for: a)
            return (st.timeIntervalSince1970, (cal.date(byAdding: .day, value: 1, to: st) ?? st).timeIntervalSince1970, false)
        case 1:
            let e = cal.date(byAdding: .day, value: 1, to: cal.startOfDay(for: a)) ?? a
            let st = cal.date(byAdding: .day, value: -7, to: e) ?? e
            return (st.timeIntervalSince1970, e.timeIntervalSince1970, false)
        case 2:
            let iv = cal.dateInterval(of: .month, for: a) ?? DateInterval(start: a, duration: 30 * 86400)
            return (iv.start.timeIntervalSince1970, iv.end.timeIntervalSince1970, false)
        default:
            let iv = cal.dateInterval(of: .year, for: a) ?? DateInterval(start: a, duration: 365 * 86400)
            return (iv.start.timeIntervalSince1970, iv.end.timeIntervalSince1970, false)
        }
    }

    var canBack: Bool { return statsWindow().0 > historyStart }
    var canForward: Bool {
        let w = statsWindow()
        return !w.2 && w.1 <= Date().timeIntervalSince1970
    }

    /// стрелки: на сутки, неделю, месяц или год назад/вперёд; для своего периода — на его длину
    func shiftStats(_ dir: Int) {
        let cal = Calendar.current
        if statsPeriod == 4 {
            let a = cal.startOfDay(for: Swift.min(customFrom, customTo))
            let b = cal.startOfDay(for: Swift.max(customFrom, customTo))
            let days = (cal.dateComponents([.day], from: a, to: b).day ?? 0) + 1
            customFrom = cal.date(byAdding: .day, value: dir * days, to: a) ?? a
            customTo = cal.date(byAdding: .day, value: dir * days, to: b) ?? b
            return
        }
        let comp: Calendar.Component = statsPeriod >= 3 ? .year : (statsPeriod == 2 ? .month : .day)
        let n = statsPeriod == 1 ? 7 : 1
        statsAnchor = cal.date(byAdding: comp, value: dir * n, to: statsAnchor ?? Date())
    }

    func statsNow() {
        statsAnchor = nil
        if statsPeriod == 4 { statsPeriod = 0 }
        showPicker = false
    }

    func pickDay(_ d: Date) {
        statsAnchor = d
        statsPeriod = 0
        showPicker = false
    }

    func calTap(_ d: Date) {
        let day = Calendar.current.startOfDay(for: d)
        if pickMode == 0 { pickDay(day); return }
        if let st = rangeStart {
            customFrom = Swift.min(st, day)
            customTo = Swift.max(st, day)
            rangeStart = nil
            applyCustom()
        } else {
            rangeStart = day
        }
    }

    func setRange(_ a: Date, _ b: Date) {
        customFrom = a
        customTo = b
        rangeStart = nil
        applyCustom()
    }

    /// дни месяца, за которые есть данные
    func daysWithData(_ monthStart: Date) -> Set<Int> {
        let cal = Calendar.current
        let a = monthStart.timeIntervalSince1970
        let b = (cal.date(byAdding: .month, value: 1, to: monthStart) ?? monthStart).timeIntervalSince1970
        var out = Set<Int>()
        for (_, arr) in history {
            for pnt in arr where pnt[0] >= a && pnt[0] < b {
                out.insert(cal.component(.day, from: Date(timeIntervalSince1970: pnt[0])))
            }
        }
        return out
    }

    func applyCustom() {
        statsPeriod = 4
        showPicker = false
    }

    func togglePicker() {
        showPicker.toggle()
        if showPicker {
            rangeStart = nil
            calMonth = statsAnchor ?? Date()
        }
    }

    func statsTitle() -> String {
        let w = statsWindow()
        if w.2 { return ["Последние 24 часа", "Последние 7 дней", "Последние 30 дней", "Последний год"][Swift.min(3, statsPeriod)] }
        let cal = Calendar.current
        let a = Date(timeIntervalSince1970: w.0)
        let curYear = cal.component(.year, from: Date())
        let yr = cal.component(.year, from: a) == curYear ? "" : " yyyy"
        func d(_ t: Date, _ f: String) -> String { return dfmt(f).string(from: t).replacingOccurrences(of: ".", with: "") }
        func up(_ x: String) -> String { return x.prefix(1).uppercased() + x.dropFirst() }
        switch statsPeriod {
        case 0:
            if cal.isDateInToday(a) { return "Сегодня, " + d(a, "d MMM") }
            if cal.isDateInYesterday(a) { return "Вчера, " + d(a, "d MMM") }
            return up(d(a, "EE, d MMM" + yr))
        case 1:
            return d(a, "d MMM") + " – " + d(Date(timeIntervalSince1970: w.1 - 1), "d MMM" + yr)
        case 2:
            return up(d(a, "LLLL" + yr))
        case 3:
            return d(a, "yyyy")
        default:
            return d(a, "d MMM yyyy") + " – " + d(Date(timeIntervalSince1970: w.1 - 1), "d MMM yyyy")
        }
    }

    /// сжимаем старые данные: свежие две недели — как есть, старше — по 30 минут, старше двух лет — по часу.
    /// История копится без ограничения по сроку, а файл остаётся небольшим.
    static func compactSeries(_ arr: [[Double]], now: Double) -> [[Double]] {
        let t1 = floor((now - 14 * 86400) / 1800) * 1800
        let t2 = floor((now - 730 * 86400) / 3600) * 3600
        var hourly: [Int: (Double, Int)] = [:]
        var half: [Int: (Double, Int)] = [:]
        var recent: [[Double]] = []
        for p in arr {
            if p[0] < t2 {
                let k = Int(floor(p[0] / 3600)); let a = hourly[k] ?? (0, 0); hourly[k] = (a.0 + p[1], a.1 + 1)
            } else if p[0] < t1 {
                let k = Int(floor(p[0] / 1800)); let a = half[k] ?? (0, 0); half[k] = (a.0 + p[1], a.1 + 1)
            } else {
                recent.append(p)
            }
        }
        var out: [[Double]] = []
        for k in hourly.keys.sorted() { let a = hourly[k]!; out.append([Double(k) * 3600 + 1800, a.0 / Double(a.1)]) }
        for k in half.keys.sorted() { let a = half[k]!; out.append([Double(k) * 1800 + 900, a.0 / Double(a.1)]) }
        return out + recent
    }

    func compactAll() {
        let now = Date().timeIntervalSince1970
        var h = history
        for (k, v) in h { h[k] = HomeModel.compactSeries(v, now: now) }
        history = h
        historyDirty = true
        lastCompact = now
    }
    var scrubs: [String: ScrubState] = [:]
    func scrub(_ k: String) -> ScrubState {
        if let x = scrubs[k] { return x }
        let n = ScrubState()
        scrubs[k] = n
        return n
    }
    var historyDirty = false
    static let tracked = ["temperature", "humidity", "co2_level", "pressure", "power"]

    var historyURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
        let dir = base.appendingPathComponent("YaHome", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("history.json")
    }

    func loadHistory() {
        guard let d = try? Data(contentsOf: historyURL) else { return }
        guard let raw = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else {
            quarantineHistory()      // файл повреждён: сохраняем копию и начинаем с чистого листа
            return
        }
        // каждая точка — [время, значение]; всё остальное отбрасываем, чтобы не падать на индексах [0] и [1]
        var clean: [String: [[Double]]] = [:]
        for (k, v) in raw {
            guard let arr = v as? [Any] else { continue }
            var pts: [[Double]] = []
            for e in arr {
                guard let p = e as? [Any], p.count >= 2,
                      let t = (p[0] as? NSNumber)?.doubleValue, let x = (p[1] as? NSNumber)?.doubleValue,
                      t.isFinite, x.isFinite, t > 0 else { continue }
                pts.append([t, x])
            }
            pts.sort { $0[0] < $1[0] }
            if !pts.isEmpty { clean[k] = pts }
        }
        history = clean
        compactAll()
        historyDirty = true
        saveHistory()
    }

    private func quarantineHistory() {
        let url = historyURL
        let bad = url.deletingLastPathComponent().appendingPathComponent("history.corrupt.json")
        try? FileManager.default.removeItem(at: bad)
        try? FileManager.default.moveItem(at: url, to: bad)
        log("history.json повреждён, копия: history.corrupt.json")
    }

    /// запись истории идёт строго по очереди: два сохранения подряд не перетрут друг друга
    static let historyQueue = DispatchQueue(label: "local.yahome.history", qos: .utility)

    func saveHistory() {
        guard historyDirty else { return }
        historyDirty = false
        let snap = history
        let url = historyURL
        HomeModel.historyQueue.async {
            if let d = try? JSONSerialization.data(withJSONObject: snap) { try? d.write(to: url, options: .atomic) }
        }
    }

    /// запоминаем показания не чаще раза в 5 минут на каждый датчик
    func record() {
        let now = Date().timeIntervalSince1970
        var h = history
        var changed = false
        for d in allDevices where d.online && !d.isKettle {
            for p in d.props where HomeModel.tracked.contains(p.instance) {
                if p.instance == "power" && d.on != true { continue }
                let k = d.id + "|" + p.instance
                var arr = h[k] ?? []
                if let last = arr.last, now - last[0] < 290 { continue }
                arr.append([now, p.value])
                h[k] = arr
                changed = true
            }
        }
        if changed {
            history = h
            historyDirty = true
            if now - lastCompact > 86400 { compactAll() }
            saveHistory()
        }
    }

    // MARK: яркость прокруткой над плиткой

    var scrollWork: DispatchWorkItem?

    /// горизонтальный свайп по трекпаду или колёсико с ⌥ над включённой лампой меняют яркость
    func scrollTile(_ e: NSEvent) -> Bool {
        guard let key = hover, let bar = key.firstIndex(of: "|") else { return false }
        let id = String(key[key.index(after: bar)...])
        guard let d = device(id), d.online, d.on == true, let br = d.bright else { return false }
        let horiz = abs(e.scrollingDeltaX) > abs(e.scrollingDeltaY) * 1.2
        let alt = e.modifierFlags.contains(.option)
        guard horiz || alt else { return false }
        var delta = Double(horiz ? e.scrollingDeltaX : e.scrollingDeltaY)
        if horiz { delta = -delta }
        delta *= e.hasPreciseScrollingDeltas ? 0.35 : 3
        if delta == 0 { return true }
        let k = d.id + ".brightness"
        let cur = draft[k] ?? br.value
        draft[k] = Swift.max(Swift.max(1, br.min), Swift.min(br.max, cur + delta))
        scrollWork?.cancel()
        let w = DispatchWorkItem { [weak self] in
            guard let s = self, let v = s.draft[k] else { return }
            s.setRange(id, "brightness", v.rounded())
            s.draft[k] = nil
        }
        scrollWork = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.45, execute: w)
        return true
    }

    var householdName: String {
        for h in households where h.id == hh { return h.name }
        return households.first?.name ?? "Мой дом"
    }

    var scopedRooms: [Room] {
        if households.count < 2 { return rooms }
        return rooms.filter { $0.hh == hh || $0.hh.isEmpty }
    }

    var allDevices: [Dev] {
        var out: [Dev] = []
        for r in scopedRooms { out.append(contentsOf: r.devices) }
        return out
    }

    var busyDevices: [Dev] { return allDevices.filter { $0.busy } }

    var litCount: Int { return allDevices.filter { $0.on == true && $0.online }.count }

    var visibleRooms: [Room] {
        var out: [Room] = []
        for r in scopedRooms {
            var ds = r.devices
            if let f = filter { ds = ds.filter { f == "offline" ? !$0.online : $0.cat == f } }
            else if !showOffline { ds = ds.filter { $0.online } }
            if !ds.isEmpty { var c = r; c.devices = ds; out.append(c) }
        }
        return out
    }

    func device(_ id: String) -> Dev? {
        for r in rooms { for d in r.devices where d.id == id { return d } }
        return nil
    }

    func roomName(_ d: Dev) -> String {
        for r in rooms where r.devices.contains(where: { $0.id == d.id }) { return r.name }
        return ""
    }

    func toggleFilter(_ k: String) { filter = filter == k ? nil : k }

    // MARK: избранное

    var favDevices: [Dev] {
        var out: [Dev] = []
        let scoped = Set(allDevices.map { $0.id })
        for id in favs where scoped.contains(id) {
            if let d = device(id), showOffline || d.online { out.append(d) }
        }
        return out
    }

    func isFav(_ id: String) -> Bool { return favs.contains(id) }

    func toggleFav(_ id: String) {
        if let i = favs.firstIndex(of: id) {
            favs.remove(at: i)
            if let d = device(id) { flash("«" + d.name + "» убрано из избранного") }
        } else {
            favs.append(id)
            if let d = device(id) { flash("«" + d.name + "» в избранном ★") }
        }
    }

    func moveFav(_ id: String, _ by: Int) {
        guard let i = favs.firstIndex(of: id) else { return }
        let j = Swift.max(0, Swift.min(favs.count - 1, i + by))
        if i == j { return }
        var f = favs
        let x = f.remove(at: i)
        f.insert(x, at: j)
        favs = f
    }

    // MARK: порядок комнат

    func ordered(_ rs: [Room]) -> [Room] {
        let order = roomOrder
        let idx = Array(rs.enumerated())
        return idx.sorted { a, b in
            let ia = order.firstIndex(of: a.element.id) ?? Int.max
            let ib = order.firstIndex(of: b.element.id) ?? Int.max
            if ia != ib { return ia < ib }
            return a.offset < b.offset
        }.map { $0.element }
    }

    func moveRoom(_ id: String, _ by: Int) {
        var ids = rooms.map { $0.id }
        guard let i = ids.firstIndex(of: id) else { return }
        // двигаем среди комнат текущего дома, перескакивая чужие
        let mine = Set(scopedRooms.map { $0.id })
        var j = i
        if by <= -1000 {
            guard let f = ids.firstIndex(where: { mine.contains($0) }) else { return }
            j = f
        } else if by >= 1000 {
            guard let l = ids.lastIndex(where: { mine.contains($0) }) else { return }
            j = l
        } else {
            repeat { j += by } while j >= 0 && j < ids.count && !mine.contains(ids[j])
        }
        guard j >= 0 && j < ids.count, j != i else { return }
        let x = ids.remove(at: i)
        ids.insert(x, at: j)
        roomOrder = ids
        rooms = ordered(rooms)
    }

    /// перетаскивание: комната встаёт на место той, над которой её держат
    func moveRoomTo(_ dragged: String, _ target: String) {
        guard dragged != target else { return }
        var ids = rooms.map { $0.id }
        guard let i = ids.firstIndex(of: dragged), let j = ids.firstIndex(of: target) else { return }
        let x = ids.remove(at: i)
        ids.insert(x, at: j)
        roomOrder = ids
        withAnimation(.easeInOut(duration: 0.18)) { rooms = ordered(rooms) }
    }

    func resetRoomOrder() {
        roomOrder = []
        rooms = rooms.sorted { a, b in a.name == b.name ? a.id < b.id : byName(a.name, b.name) }
    }

    func toggleCollapse(_ id: String) {
        if collapsed.contains(id) { collapsed.remove(id) } else { collapsed.insert(id) }
    }

    func pickHousehold(_ id: String) {
        hh = id
        filter = nil
        ud.set(id, forKey: "hh")
        notifyStatus()
    }

    // MARK: вход

    func accept(_ t: String) {
        let clean = t.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { return }
        guard Keychain.set(clean) else {
            // токен не сохранён — вход не считаем успешным
            waiting = false
            server.stop()
            error = "Не удалось сохранить токен в связке ключей macOS. Вход не выполнен: разблокируйте связку ключей и повторите."
            return
        }
        token = clean
        waiting = false
        error = nil
        server.stop()
        NSApp.activate(ignoringOtherApps: true)
        refresh()
    }

    func login() {
        error = nil
        let state = UUID().uuidString
        server.expectedState = state
        let ru = redirectURI.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? redirectURI
        let started = server.start { [weak self] in
            // браузер открываем только когда приёмник готов принимать ответ
            if self?.waiting == true,
               let u = URL(string: "https://oauth.yandex.ru/authorize?response_type=token&client_id=\(clientID)&redirect_uri=\(ru)&state=\(state)") {
                NSWorkspace.shared.open(u)
            }
        }
        guard started else {
            waiting = false
            error = "Не удалось запустить приёмник входа: порт \(loopPort) занят другой программой. Закройте её и повторите или вставьте токен вручную ниже."
            return
        }
        waiting = true
    }

    /// Запасной способ входа: пользователь сам вставляет токен (или адрес с access_token).
    /// Это осознанное действие человека, а не ответ браузера, поэтому `state` здесь не проверяется.
    func acceptManual() {
        let s = manual
        if let t = AuthServer.extractToken(s) { accept(t) } else { accept(s) }
        manual = ""
    }

    func logout() {
        Keychain.set(nil)
        token = nil
        rooms = []
        scenarios = []
        error = nil
        showSettings = false
        tab = 0
        timer?.invalidate()
        notifyStatus()
    }

    func flash(_ s: String, long: Bool = false) {
        toast = s
        DispatchQueue.main.asyncAfter(deadline: .now() + (long ? 6 : 2.5)) { [weak self] in
            if self?.toast == s { self?.toast = nil }
        }
    }

    // MARK: сеть

    func api(_ method: String, _ path: String, _ body: [String: Any]?, _ done: @escaping (Int, [String: Any]?) -> Void) {
        guard let tok = token, let url = URL(string: apiBase + path) else { done(0, nil); return }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = 12
        req.setValue("Bearer " + tok, forHTTPHeaderField: "Authorization")
        if let b = body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try? JSONSerialization.data(withJSONObject: b)
        }
        URLSession.shared.dataTask(with: req) { data, resp, _ in
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            var json: [String: Any]?
            if let d = data { json = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] }
            DispatchQueue.main.async { done(code, json) }
        }.resume()
    }

    func refresh() {
        guard token != nil, !loading else { return }
        loading = true
        api("GET", "/user/info", nil) { [weak self] code, json in
            guard let s = self else { return }
            s.loading = false
            if code == 401 || code == 403 {
                Keychain.set(nil)
                s.token = nil
                s.error = "Доступ закрыт. Войдите снова."
                s.notifyStatus()
                return
            }
            if code == 200, let j = json {
                s.error = nil
                s.parse(j)
                s.verifyOn()
            } else {
                s.error = code == 0 ? "Нет связи с Яндексом" : "Ошибка Яндекса (\(code))"
            }
            s.schedule()
        }
    }

    /// как часто спрашивать состояние: пока что-то готовится — каждые 4 секунды
    var busyTicks = 0
    var watchUntil: [String: Date] = [:]

    /// пока что-то греется/работает — каждые 3 секунды спрашиваем само устройство напрямую
    /// (общий список у Яндекса обновляется с задержкой), раз в 30 секунд — весь дом
    func schedule() {
        timer?.invalidate()
        guard token != nil else { return }
        let now = Date()
        watchUntil = watchUntil.filter { $0.value > now }
        var ids = Set(busyDevices.map { $0.id })
        for k in watchUntil.keys { ids.insert(k) }
        if !ids.isEmpty {
            let fast = busyDevices.contains { $0.isKettle }
            timer = Timer.scheduledTimer(withTimeInterval: fast ? 1.5 : 3, repeats: false) { [weak self] _ in
                guard let s = self else { return }
                s.busyTicks += 1
                if s.busyTicks % 20 == 0 {
                    s.refresh()
                } else {
                    for id in ids { s.pollDevice(id) }
                    s.schedule()
                }
            }
            return
        }
        busyTicks = 0
        let iv: TimeInterval = isOpen ? 6 : 60
        timer = Timer.scheduledTimer(withTimeInterval: iv, repeats: false) { [weak self] _ in self?.refresh() }
    }

    /// свежее состояние одного устройства
    func pollDevice(_ id: String) {
        api("GET", "/devices/" + id, nil) { [weak self] code, json in
            guard let s = self, code == 200, let j = json, let old = s.device(id) else { return }
            var d = Dev(raw: j)
            d.roomID = old.roomID
            d.hhID = old.hhID
            d.name = old.name
            s.strip(&d)
            s.applyPending(&d)
            let t = d.props.first(where: { $0.instance == "temperature" })
            s.log("опрос \(old.name): on=\(d.on.map { String($0) } ?? "-") t=\(t.map { Dev.num($0.value) } ?? "-") обновлено \(t.map { Int(Date().timeIntervalSince1970 - $0.updated) } ?? -1) с назад")
            let nd = d
            s.mutate(id) { $0 = nd }
            s.detectDone()
            s.notifyStatus()
        }
    }

    /// только что изменённое пользователем не «откатывается» старым ответом сервера
    func applyPending(_ d: inout Dev) {
        let now = Date()
        for (k, v) in pending where k.hasPrefix(d.id + "|") {
            if v.0 > now { v.1(&d) }
        }
    }

    /// убираем кнопки, которые Яндекс для этого устройства не принимает
    func strip(_ d: inout Dev) {
        let p = d.id + "|"
        if badCaps.contains(p + "on_off|on") { d.on = nil }
        d.ranges.removeAll { badCaps.contains(p + "range|" + $0.instance) }
        d.modes.removeAll { badCaps.contains(p + "mode|" + $0.instance) }
        d.toggles.removeAll { badCaps.contains(p + "toggle|" + $0.instance) }
        if badCaps.contains(p + "color_setting|scene") { d.color?.scenes = [] }
        if badCaps.contains(p + "color_setting|rgb") || badCaps.contains(p + "color_setting|hsv") { d.color?.model = "" }
        if badCaps.contains(p + "color_setting|temperature_k") { d.color?.hasTK = false }
        if let c = d.color, c.model.isEmpty, !c.hasTK, c.scenes.isEmpty { d.color = nil }
    }

    func parse(_ j: [String: Any]) {
        let now = Date()
        pending = pending.filter { $0.value.0 > now }
        var byRoom: [String: [Dev]] = [:]
        for r in j["devices"] as? [[String: Any]] ?? [] {
            var d = Dev(raw: r)
            strip(&d)
            applyPending(&d)
            byRoom[d.roomID, default: []].append(d)
        }
        for k in byRoom.keys {
            byRoom[k]?.sort { a, b in a.name == b.name ? a.id < b.id : byName(a.name, b.name) }
        }
        var out: [Room] = []
        var known = Set<String>()
        for r in j["rooms"] as? [[String: Any]] ?? [] {
            let id = r["id"] as? String ?? ""
            known.insert(id)
            if let ds = byRoom[id], !ds.isEmpty {
                out.append(Room(hh: r["household_id"] as? String ?? "", id: id, name: r["name"] as? String ?? "Комната", devices: ds))
            }
        }
        var rest: [Dev] = []
        for (k, v) in byRoom where !known.contains(k) { rest.append(contentsOf: v) }
        if !rest.isEmpty {
            var byHH: [String: [Dev]] = [:]
            for d in rest { byHH[d.hhID, default: []].append(d) }
            for (k, v) in byHH {
                let sorted = v.sorted { a, b in a.name == b.name ? a.id < b.id : byName(a.name, b.name) }
                out.append(Room(hh: k, id: "none" + k, name: "Не подключено", devices: sorted))
            }
        }
        // порядок комнат — по алфавиту, как в приложении «Дом с Алисой»
        out.sort { a, b in a.name == b.name ? a.id < b.id : byName(a.name, b.name) }
        out = ordered(out)
        var hhs: [Household] = []
        for h in j["households"] as? [[String: Any]] ?? [] {
            if let id = h["id"] as? String { hhs.append(Household(id: id, name: h["name"] as? String ?? "Дом")) }
        }
        households = hhs
        if !hhs.contains(where: { $0.id == hh }) { hh = hhs.first?.id ?? "" }
        rooms = out
        var sc: [Scen] = []
        for s in j["scenarios"] as? [[String: Any]] ?? [] {
            if let id = s["id"] as? String, let n = s["name"] as? String { sc.append(Scen(id: id, name: n)) }
        }
        scenarios = sc.sorted { byName($0.name, $1.name) }
        detectDone()
        record()
        notifyStatus()
    }

    /// чайник закипел: звук и надпись в строке меню
    func detectDone() {
        var now = Set<String>()
        for d in allDevices where d.heating { now.insert(d.id) }
        for id in heatingIDs.subtracting(now) {
            guard let d = device(id), d.online else { continue }
            if d.on == true {
                announce(d.name + " готов")
            } else if let c = d.curTemp, let t = d.target, c >= t.value - 3 {
                announce(d.name + " готов")
            }
        }
        heatingIDs = now
    }

    func announce(_ s: String) {
        doneMsg = s
        if doneSound { NSSound(named: NSSound.Name("Glass"))?.play() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self] in
            if self?.doneMsg == s { self?.doneMsg = nil; self?.notifyStatus() }
        }
    }

    func notifyStatus() { onStatus?() }

    // MARK: что показывать в строке меню

    var tempSources: [Dev] {
        return allDevices.filter { d in d.props.contains { $0.instance == "temperature" } }
    }

    var switchable: [Dev] {
        return allDevices.filter { $0.on != nil }
    }

    func barContentOld(_ phase: Int) -> (String, String) {
        if token == nil { return ("house", "") }
        if barBusy, let d = busyDevices.first {
            if d.isKettle {
                let sym = phase % 2 == 0 ? "flame.fill" : "flame"
                if let c = d.curTemp { return (sym, Dev.num(c) + "°") }
                return (sym, "…")
            }
            return (phase % 2 == 0 ? "sparkles" : "sparkle", "")
        }
        if let s = doneMsg { return ("checkmark.circle.fill", s) }
        let lit = litCount
        switch barMode {
        case "count":
            return (lit > 0 ? "house.fill" : "house", lit > 0 ? String(lit) : "")
        case "lights":
            let n = allDevices.filter { $0.cat == "light" && $0.on == true && $0.online }.count
            return (n > 0 ? "lightbulb.fill" : "lightbulb", n > 0 ? String(n) : "")
        case "temp":
            if let d = device(barDevice), let t = d.props.first(where: { $0.instance == "temperature" }) {
                var s = Dev.num(t.value) + "°"
                if let h = d.props.first(where: { $0.instance == "humidity" }) { s += "  " + String(Int(h.value.rounded())) + "%" }
                return ("thermometer.medium", s)
            }
            return ("thermometer.medium", "—")
        case "device":
            if let d = device(barDevice) {
                if !d.online { return (d.symbol, "нет сети") }
                if let c = d.curTemp { return (d.symbol, Dev.num(c) + "°") }
                if d.on == true, let b = d.bright { return (d.symbol, String(Int(b.value.rounded())) + "%") }
                return (d.symbol, d.on == true ? "вкл" : "выкл")
            }
            return ("house", "")
        default:
            return (lit > 0 ? "house.fill" : "house", "")
        }
    }

    static func loadBar() -> [String] {
        if let a = ud.array(forKey: "barItems") as? [String] { return a }
        let mode = ud.string(forKey: "barMode") ?? "count"
        let dev = ud.string(forKey: "barDevice") ?? ""
        switch mode {
        case "icon": return ["home"]
        case "lights": return ["home", "lights"]
        case "temp": return dev.isEmpty ? ["home:count"] : ["home", "temp:" + dev]
        case "device": return dev.isEmpty ? ["home:count"] : ["home", "dev:" + dev]
        default: return ["home:count"]
        }
    }

    var humSources: [Dev] { return allDevices.filter { d in d.props.contains { $0.instance == "humidity" } } }
    var co2Sources: [Dev] { return allDevices.filter { d in d.props.contains { $0.instance == "co2_level" } } }

    func propOf(_ id: String, _ inst: String) -> Double? {
        return device(id)?.props.first(where: { $0.instance == inst })?.value
    }

    /// один элемент строки меню: значок и текст
    func barSegment(_ it: String) -> (String, String)? {
        let parts = it.split(separator: ":", maxSplits: 1).map(String.init)
        let kind = parts[0]
        let arg = parts.count > 1 ? parts[1] : ""
        let lit = litCount
        switch kind {
        case "home":
            if arg == "count" { return (lit > 0 ? "house.fill" : "house", lit > 0 ? String(lit) : "") }
            return (lit > 0 ? "house.fill" : "house", "")
        case "lights":
            let n = allDevices.filter { $0.cat == "light" && $0.on == true && $0.online }.count
            return (n > 0 ? "lightbulb.fill" : "lightbulb", String(n))
        case "temp":
            guard let v = propOf(arg, "temperature") else { return ("", "—") }
            return ("", Dev.num(v) + "°")
        case "hum":
            guard let v = propOf(arg, "humidity") else { return ("", "—") }
            return ("", String(Int(v.rounded())) + "%")
        case "co2":
            guard let v = propOf(arg, "co2_level") else { return ("aqi.medium", "—") }
            return ("aqi.medium", String(Int(v.rounded())))
        case "dev":
            guard let d = device(arg) else { return nil }
            if !d.online { return (d.symbol, "нет сети") }
            if let s = d.stationLight { return (d.symbol, sceneTitle(s)) }
            if d.on == nil, let c = d.curTemp { return (d.symbol, Dev.num(c) + "°") }
            if d.on == true {
                if let b = d.bright { return (d.symbol, String(Int(b.value.rounded())) + "%") }
                if let t = d.target, d.cat == "climate" { return (d.symbol, Dev.num(t.value) + "°") }
                return (d.symbol, "вкл")
            }
            return (d.symbol, d.on == false ? "выкл" : "")
        default:
            return nil
        }
    }

    /// всё, что сейчас показывается в строке меню
    func barSegments(_ phase: Int) -> [(String, String)] {
        if token == nil { return [("house", "")] }
        if let s = doneMsg { return [("checkmark.circle.fill", s)] }
        var out: [(String, String)] = []
        if barBusy, let d = busyDevices.first {
            if d.isKettle {
                let sym = phase % 2 == 0 ? "flame.fill" : "flame"
                if let c = d.curTemp, d.tempFresh { out.append((sym, Dev.num(c) + "°")) } else { out.append((sym, "")) }
            } else {
                out.append((phase % 2 == 0 ? "sparkles" : "sparkle", ""))
            }
        }
        for it in barItems {
            if let s = barSegment(it) { out.append(s) }
        }
        if out.isEmpty { out.append(("house", "")) }
        return out
    }

    /// подписи для настроек
    func barItemInfo(_ it: String) -> (String, String, String) {
        let parts = it.split(separator: ":", maxSplits: 1).map(String.init)
        let arg = parts.count > 1 ? parts[1] : ""
        func dn() -> String {
            if let d = device(arg) { return d.name + " · " + roomName(d) }
            return "устройство не найдено"
        }
        switch parts[0] {
        case "home": return (arg == "count" ? "house.fill" : "house", arg == "count" ? "Дом и сколько включено" : "Значок дома", "")
        case "lights": return ("lightbulb.fill", "Сколько горит света", "")
        case "temp": return ("thermometer.medium", "Температура", dn())
        case "hum": return ("humidity", "Влажность", dn())
        case "co2": return ("aqi.medium", "CO₂", dn())
        case "dev": return (device(arg)?.symbol ?? "circle", device(arg)?.name ?? "Устройство", device(arg).map { roomName($0) } ?? "")
        default: return ("questionmark", it, "")
        }
    }

    func addBar(_ it: String) {
        if barItems.contains(it) { return }
        var a = barItems
        // «дом» и «дом со счётом» взаимоисключающие
        if it.hasPrefix("home") { a.removeAll { $0.hasPrefix("home") }; a.insert(it, at: 0) } else { a.append(it) }
        barItems = a
    }

    func removeBar(_ it: String) { barItems.removeAll { $0 == it } }

    func moveBar(_ it: String, _ by: Int) {
        guard let i = barItems.firstIndex(of: it) else { return }
        let j = Swift.max(0, Swift.min(barItems.count - 1, i + by))
        if i == j { return }
        var a = barItems
        let x = a.remove(at: i)
        a.insert(x, at: j)
        barItems = a
    }

    func setBarMode(_ k: String) {
        barMode = k
        if k == "temp", !tempSources.contains(where: { $0.id == barDevice }) { barDevice = tempSources.first?.id ?? "" }
        if k == "device", !switchable.contains(where: { $0.id == barDevice }) { barDevice = switchable.first?.id ?? "" }
    }

    // MARK: управление

    func mutate(_ id: String, _ f: (inout Dev) -> Void) {
        for i in rooms.indices {
            for k in rooms[i].devices.indices where rooms[i].devices[k].id == id {
                f(&rooms[i].devices[k])
            }
        }
    }

    /// меняем сразу на экране и запоминаем на 8 секунд, пока устройство не подтвердит
    func hold(_ id: String, _ key: String, _ f: @escaping (inout Dev) -> Void) {
        pending[id + "|" + key] = (Date().addingTimeInterval(8), f)
        mutate(id, f)
    }

    /// понятное объяснение ошибки Яндекса
    func errText(_ code: String, _ msg: String?) -> String {
        switch code {
        case "DEVICE_UNREACHABLE": return "устройство недоступно — оно выключено из розетки, без Wi‑Fi или потеряло связь с облаком производителя"
        case "DEVICE_BUSY": return "устройство занято, попробуйте чуть позже"
        case "DEVICE_NOT_FOUND": return "устройство не найдено"
        case "INVALID_ACTION": return "такую команду устройство не принимает"
        case "INVALID_VALUE": return "недопустимое значение"
        case "NOT_SUPPORTED_IN_CURRENT_MODE": return "нельзя в текущем режиме (вода, крышка, подставка?)"
        case "REMOTE_CONTROL_DISABLED": return "удалённое управление выключено на самом устройстве"
        case "ACCOUNT_LINKING_ERROR": return "нужно заново привязать аккаунт производителя в «Доме с Алисой»"
        case "INTERNAL_ERROR": return "ошибка у производителя устройства"
        case "UNKNOWN_ERROR": return "облако производителя не выполнило команду. Скорее всего, устройство потеряло связь с приложением производителя — переподключите его там, затем в «Доме с Алисой» обновите список устройств производителя"
        default:
            if let m = msg, !m.isEmpty { return m }
            return code.isEmpty ? "не ответило" : code
        }
    }

    /// журнал команд: ~/Library/Logs/YaHome.log (для разбора проблем)
    func log(_ s: String) {
        let url = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/YaHome.log")
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let line = df.string(from: Date()) + "  " + s + "\n"
        guard let data = line.data(using: .utf8) else { return }
        // ротация: при превышении ~1 МБ старый журнал уходит в YaHome.log.1 (один архивный файл)
        if let sz = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? Int, sz > 1_000_000 {
            let old = url.appendingPathExtension("1")
            try? FileManager.default.removeItem(at: old)
            try? FileManager.default.moveItem(at: url, to: old)
        }
        if let h = try? FileHandle(forWritingTo: url) {
            h.seekToEndOfFile()
            h.write(data)
            try? h.close()
        } else {
            try? data.write(to: url)
        }
    }

    func jsonText(_ o: Any?) -> String {
        guard let o = o, JSONSerialization.isValidJSONObject(o),
              let d = try? JSONSerialization.data(withJSONObject: o), let s = String(data: d, encoding: .utf8) else { return "—" }
        return s
    }

    func send(_ devices: [[String: Any]], retry: Bool = true) {
        let body: [String: Any] = ["devices": devices]
        var ids: [String] = []
        for d in devices { if let i = d["id"] as? String { ids.append(i) } }
        api("POST", "/devices/actions", body) { [weak self] code, json in
            guard let s = self else { return }
            s.log("→ " + s.jsonText(body) + "\n   ← \(code) " + s.jsonText(json))
            var errs: [String] = []
            var codes: [String] = []
            var failed = Set<String>()
            if code == 0 {
                errs.append("нет связи с Яндексом")
                failed = Set(ids)
            } else if code != 200 {
                let msg = (json?["message"] as? String) ?? ""
                // «action devices.capabilities.on_off:on is not valid for device …»
                if msg.contains("is not valid for device"),
                   let re = try? NSRegularExpression(pattern: "devices\\.capabilities\\.([a-z_]+):([A-Za-z0-9_.]+) is not valid for device ([0-9a-fA-F-]+)"),
                   let mt = re.firstMatch(in: msg, range: NSRange(msg.startIndex..., in: msg)),
                   let r1 = Range(mt.range(at: 1), in: msg), let r2 = Range(mt.range(at: 2), in: msg), let r3 = Range(mt.range(at: 3), in: msg) {
                    let did = String(msg[r3])
                    s.badCaps.insert(did + "|" + String(msg[r1]) + "|" + String(msg[r2]))
                    errs.append("Яндекс не даёт так управлять этим устройством из приложений — лишнюю кнопку я убрал")
                    failed = [did]
                    s.pending = s.pending.filter { !$0.key.hasPrefix(did + "|") }
                    if var d = s.device(did) { s.strip(&d); let dd = d; s.mutate(did) { $0 = dd } }
                } else {
                    errs.append(msg.isEmpty ? "ошибка Яндекса (\(code))" : msg)
                    failed = Set(ids)
                }
            }
            for d in json?["devices"] as? [[String: Any]] ?? [] {
                let did = d["id"] as? String ?? ""
                for c in d["capabilities"] as? [[String: Any]] ?? [] {
                    let st = c["state"] as? [String: Any]
                    let ar = st?["action_result"] as? [String: Any]
                    if ((ar?["status"] as? String) ?? "").uppercased() == "ERROR" {
                        failed.insert(did)
                        let ec = ar?["error_code"] as? String ?? ""
                        codes.append(ec)
                        if ec == "DEVICE_UNREACHABLE", let dv = s.device(did), dv.isKettle, dv.online {
                            errs.append("производитель не пускает команду к чайнику. Многие чайники (например, Xiaomi) из соображений безопасности не дают запускать кипячение удалённо — только видеть температуру и поддерживать тепло")
                        } else {
                            errs.append(s.errText(ec, ar?["error_message"] as? String))
                        }
                    }
                }
            }
            // производитель иногда отвечает «неизвестной ошибкой» с первого раза — пробуем ещё раз
            let soft: Set<String> = ["UNKNOWN_ERROR", "DEVICE_BUSY", "INTERNAL_ERROR"]
            if retry, !codes.isEmpty, errs.count == codes.count, codes.allSatisfy({ soft.contains($0) }) {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { s.send(devices, retry: false) }
                return
            }
            for id in failed { noAnswer[id] = Date() }
            if errs.isEmpty { for id in ids { noAnswer[id] = nil } }
            if let e = errs.first {
                // откатываем показанное заранее состояние
                for id in failed { s.pending = s.pending.filter { !$0.key.hasPrefix(id + "|") } }
                var who = "Устройство"
                if failed.count == 1, let f = failed.first, let d = s.device(f) { who = d.name }
                if failed.count > 1 { who = "Несколько устройств" }
                s.flash(who + ": " + e, long: true)
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { s.refresh() }
            } else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { s.refresh() }
            }
        }
    }

    func sendCap(_ id: String, _ action: [String: Any]) {
        send([["id": id, "actions": [action]]])
    }

    /// нажатие «кнопки» устройства (например, ИК-пульт)
    func pressButton(_ id: String, _ o: OtherCap) {
        // импульсную команду нельзя повторять автоматически: неоднозначный ответ не должен нажать «кнопку» дважды
        send([["id": id, "actions": [["type": o.type, "state": ["instance": o.instance, "value": true]]]]], retry: false)
    }

    /// вернуть кнопки, которые виджет спрятал после отказа Яндекса
    func restoreCaps(_ id: String) {
        badCaps = badCaps.filter { !$0.hasPrefix(id + "|") }
        refresh()
    }

    func onAction(_ on: Bool) -> [String: Any] {
        return ["type": "devices.capabilities.on_off", "state": ["instance": "on", "value": on]]
    }

    func setOn(_ id: String, _ on: Bool) {
        hold(id, "on") { $0.on = on }
        watchUntil[id] = Date().addingTimeInterval((device(id)?.isKettle ?? false) ? 600 : 20)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [weak self] in self?.schedule() }
        notifyStatus()
        send([["id": id, "actions": [onAction(on)]]])
    }

    func setRoom(_ room: Room, on: Bool) {
        var list: [[String: Any]] = []
        for d in room.devices where d.on != nil && d.online {
            hold(d.id, "on") { $0.on = on }
            list.append(["id": d.id, "actions": [onAction(on)]])
        }
        notifyStatus()
        if !list.isEmpty { send(list) }
    }

    func setCategory(_ key: String, on: Bool) {
        var list: [[String: Any]] = []
        for d in allDevices where d.cat == key && d.on != nil && d.online {
            hold(d.id, "on") { $0.on = on }
            list.append(["id": d.id, "actions": [onAction(on)]])
        }
        notifyStatus()
        if !list.isEmpty { send(list) }
    }

    func setRange(_ id: String, _ instance: String, _ v: Double) {
        hold(id, "r." + instance) { d in
            for i in d.ranges.indices where d.ranges[i].instance == instance { d.ranges[i].value = v }
        }
        sendCap(id, ["type": "devices.capabilities.range", "state": ["instance": instance, "value": v]])
    }

    func setMode(_ id: String, _ instance: String, _ v: String) {
        hold(id, "m." + instance) { d in
            for i in d.modes.indices where d.modes[i].instance == instance { d.modes[i].value = v }
        }
        sendCap(id, ["type": "devices.capabilities.mode", "state": ["instance": instance, "value": v]])
    }

    func setToggle(_ id: String, _ instance: String, _ v: Bool) {
        hold(id, "t." + instance) { d in
            for i in d.toggles.indices where d.toggles[i].instance == instance { d.toggles[i].value = v }
        }
        sendCap(id, ["type": "devices.capabilities.toggle", "state": ["instance": instance, "value": v]])
    }

    func setHue(_ id: String, _ h: Double, _ s: Double) {
        let model = device(id)?.color?.model ?? ""
        let rgb = rgbInt(h: h, s: s / 100, v: 1)
        hold(id, "color") { d in
            d.color?.rgb = rgb
            d.color?.current = "rgb"
            d.on = true
        }
        if model == "hsv" {
            sendCap(id, ["type": "devices.capabilities.color_setting",
                         "state": ["instance": "hsv", "value": ["h": Int(h), "s": Int(s), "v": 100]]])
        } else {
            sendCap(id, ["type": "devices.capabilities.color_setting", "state": ["instance": "rgb", "value": rgb]])
        }
    }

    func setTK(_ id: String, _ k: Double) {
        hold(id, "color") { d in
            d.color?.tk = k
            d.color?.current = "temperature_k"
            d.on = true
        }
        sendCap(id, ["type": "devices.capabilities.color_setting", "state": ["instance": "temperature_k", "value": Int(k)]])
    }

    func setScene(_ id: String, _ s: String) {
        hold(id, "color") { d in
            d.color?.scene = s
            d.color?.current = "scene"
            d.on = true
        }
        sendCap(id, ["type": "devices.capabilities.color_setting", "state": ["instance": "scene", "value": s]])
    }

    func run(_ s: Scen) {
        ranScenario = s.id
        api("POST", "/scenarios/\(s.id)/actions", [:]) { [weak self] code, _ in
            guard let m = self else { return }
            if code != 200 { m.flash("Сценарий не запустился") }
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                if m.ranScenario == s.id { m.ranScenario = nil }
                m.refresh()
            }
        }
    }

    // MARK: наведение на плитку

    func tileEnter(_ key: String, _ id: String) {
        guard hoverTiles, detailID == nil, tab == 0, let d = device(id), d.hasControls else { return }
        closeWork?.cancel()
        if quickID == key { return }
        openWork?.cancel()
        let w = DispatchWorkItem { [weak self] in
            guard let s = self, s.hover == key, s.detailID == nil, s.draft.isEmpty else { return }
            s.quickID = key
        }
        openWork = w
        // если панель уже открыта у другой плитки — переключаемся не сразу,
        // чтобы не «перехватить» её, пока курсор едет к панели
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0, execute: w)
    }

    func tileExit(_ key: String) {
        openWork?.cancel()
    }

    func panelHover(_ h: Bool) {
        if h { awaySince = nil }
    }

    /// панель держится, пока курсор на плитке или в самой панели;
    /// закрывается, только если курсор ушёл больше чем на 1,2 секунды
    func startQuickWatch() {
        quickTimer?.invalidate()
        awaySince = nil
        guard quickID != nil else { return }
        quickTimer = Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { [weak self] _ in self?.quickTick() }
    }

    func quickTick() {
        guard let q = quickID else { quickTimer?.invalidate(); quickTimer = nil; return }
        let p = NSEvent.mouseLocation
        var inPanel = false
        for w in NSApp.windows where w.isVisible && w !== mainWindow {
            if w.frame.insetBy(dx: -8, dy: -8).contains(p) { inPanel = true; break }
        }
        if inPanel || hover == q || !draft.isEmpty {
            awaySince = nil
            return
        }
        if let a = awaySince {
            if Date().timeIntervalSince(a) > 1.2 { quickID = nil }
        } else {
            awaySince = Date()
        }
    }

    func scheduleClose() {}

    func openDetail(_ id: String) {
        openWork?.cancel()
        quickID = nil
        withAnimation(.easeInOut(duration: 0.22)) { detailID = id }
    }

    func closeDetail() {
        withAnimation(.easeInOut(duration: 0.22)) { detailID = nil }
    }

    func opened() {
        isOpen = true
        refresh()
        schedule()
        autoCheckUpdateIfNeeded()
    }

    func closed() {
        isOpen = false
        draggingRoom = nil
        quickID = nil
        let noneIDs = Set(rooms.filter { $0.id.hasPrefix("none") || $0.name.lowercased().contains("не подключ") }.map { $0.id })
        collapsed = collapsed.filter { !noneIDs.contains($0) }
        detailID = nil
        if tab == 2 { tab = 0 }
        schedule()
    }
}

// MARK: - Цвета и стиль

func dyn(_ l: NSColor, _ d: NSColor) -> Color {
    return Color(NSColor(name: nil) { ap in
        ap.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? d : l
    })
}

func rgb(_ r: Int, _ g: Int, _ b: Int) -> NSColor {
    return NSColor(srgbRed: CGFloat(r) / 255, green: CGFloat(g) / 255, blue: CGFloat(b) / 255, alpha: 1)
}

let purple = Color(red: 0.49, green: 0.36, blue: 0.98)
let heatOrange = Color(red: 1.0, green: 0.55, blue: 0.12)
/// высота окна: до 860, но не выше экрана
func panelHeight() -> CGFloat {
    let h = NSScreen.main?.visibleFrame.height ?? 800
    return Swift.min(860, Swift.max(680, h - 50))
}

let pageBG = dyn(rgb(255, 255, 255), rgb(28, 28, 31))
let tileBG = dyn(rgb(248, 249, 252), rgb(44, 44, 49))
let tileHover = dyn(rgb(240, 242, 248), rgb(54, 54, 60))
let plateBG = Color(red: 242 / 255, green: 243 / 255, blue: 245 / 255)
let softBtn = dyn(rgb(234, 235, 241), rgb(64, 64, 72))
let cardBG = dyn(rgb(247, 248, 250), rgb(40, 40, 45))

struct Cat {
    let key: String
    let title: String
    let symbol: String
    let tint: Color
}

let allCats: [Cat] = [
    Cat(key: "light", title: "Свет", symbol: "lightbulb.fill", tint: Color(hue: 0.11, saturation: 0.7, brightness: 0.98)),
    Cat(key: "socket", title: "Розетки", symbol: "powerplug.fill", tint: Color(hue: 0.38, saturation: 0.62, brightness: 0.8)),
    Cat(key: "switch", title: "Выключатели", symbol: "switch.2", tint: Color(hue: 0.66, saturation: 0.5, brightness: 0.92)),
    Cat(key: "climate", title: "Климат", symbol: "thermometer.medium", tint: Color(hue: 0.5, saturation: 0.62, brightness: 0.82)),
    Cat(key: "media", title: "ТВ и колонки", symbol: "tv.fill", tint: Color(hue: 0.59, saturation: 0.58, brightness: 0.92)),
    Cat(key: "kitchen", title: "Кухня", symbol: "fork.knife", tint: Color(hue: 0.05, saturation: 0.6, brightness: 0.95)),
    Cat(key: "cleaning", title: "Уборка и стирка", symbol: "sparkles", tint: Color(hue: 0.54, saturation: 0.52, brightness: 0.88)),
    Cat(key: "cover", title: "Шторы и двери", symbol: "door.left.hand.closed", tint: Color(hue: 0.75, saturation: 0.45, brightness: 0.86)),
    Cat(key: "camera", title: "Камеры", symbol: "video.fill", tint: Color(hue: 0.97, saturation: 0.55, brightness: 0.9)),
    Cat(key: "meter", title: "Счётчики", symbol: "gauge.medium", tint: Color(hue: 0.56, saturation: 0.45, brightness: 0.82)),
    Cat(key: "pet", title: "Питомцы", symbol: "pawprint.fill", tint: Color(hue: 0.08, saturation: 0.5, brightness: 0.82)),
    Cat(key: "sensor", title: "Датчики", symbol: "sensor.tag.radiowaves.forward.fill", tint: Color(hue: 0.6, saturation: 0.2, brightness: 0.72)),
    Cat(key: "other", title: "Прочее", symbol: "circle.grid.2x2.fill", tint: Color(hue: 0.72, saturation: 0.3, brightness: 0.84))
]

func catFor(_ key: String) -> Cat {
    for c in allCats where c.key == key { return c }
    return allCats[allCats.count - 1]
}

extension View {
    func card() -> some View {
        return self.padding(14)
            .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(cardBG))
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Color.primary.opacity(0.05), lineWidth: 1))
    }
}

/// картинка устройства на светлой «подложке» — у всех устройств одинаковой
func rgbOf(_ c: Color) -> (Double, Double, Double) {
    let n = NSColor(c).usingColorSpace(.sRGB) ?? NSColor.white
    return (Double(n.redComponent), Double(n.greenComponent), Double(n.blueComponent))
}

func mixWhite(_ c: Color, _ f: Double) -> Color {
    let (r, g, bl) = rgbOf(c)
    return Color(red: 1 - (1 - r) * f, green: 1 - (1 - g) * f, blue: 1 - (1 - bl) * f)
}

func hueOfColor(_ c: Color) -> Double {
    let n = NSColor(c).usingColorSpace(.sRGB) ?? NSColor.white
    return Double(n.hueComponent) * 360
}

/// исходный оттенок цветных картинок ламп
func baseHue(_ k: String) -> Double? {
    switch k {
    case "lamp_pink": return 305
    case "lamp_ambi": return 300
    case "strip": return 255
    default: return nil
    }
}

/// оттенок и насыщенность света лампы сейчас
func lightTone(_ d: Dev) -> (Double, Double) {
    if let c = d.color {
        if c.current == "rgb" {
            let r = Double((c.rgb >> 16) & 255) / 255, g = Double((c.rgb >> 8) & 255) / 255, bl = Double(c.rgb & 255) / 255
            let mx = Swift.max(r, Swift.max(g, bl)), mn = Swift.min(r, Swift.min(g, bl))
            return (hueOf(c.rgb), mx > 0 ? Swift.max(0.25, (mx - mn) / mx) : 0)
        }
        if c.current == "scene" && !c.scene.isEmpty { return (hueOfColor(sceneColors(c.scene)[0]), 1) }
        if c.current == "temperature_k" {
            let k = c.tk
            if k < 4200 { return (36, 0.25 + 0.4 * Swift.max(0, (4200 - k) / 1500)) }
            if k > 5200 { return (210, 0.12 + 0.15 * Swift.min(1, (k - 5200) / 1300)) }
            return (40, 0.12)
        }
    }
    return (42, 0.55)
}

/// где у картинки «светящаяся» часть (центр по x, y и радиус — доли размера)
func glowSpot(_ k: String) -> (CGFloat, CGFloat, CGFloat) {
    switch k {
    case "bulb": return (0.5, 0.36, 0.34)
    case "lamp_white", "lamp_pink": return (0.5, 0.28, 0.36)
    case "lamp_ambi": return (0.5, 0.45, 0.42)
    case "strip": return (0.5, 0.62, 0.5)
    default: return (0.5, 0.45, 0.45)
    }
}

/// картинка устройства на прозрачном фоне с мягкой тенью.
/// Лампы всегда нарисованы «без света», а включённый свет накладывается сверху цветом режима.
struct DevImage: View {
    let d: Dev
    let size: CGFloat

    /// выключено или не в сети — картинка серая; включено — как есть.
    /// Цвет режима показывает только фон плитки, сама иконка не перекрашивается.
    var gray: Bool { return !d.online || d.on == false }

    /// размеры плашки в долях от клетки: ширина, высота, скругление
    static func geometry(_ key: String?) -> (w: CGFloat, h: CGFloat, round: CGFloat) {
        switch key ?? "" {
        case "lite": return (0.50, 0.50, 0.5)
        case "mini": return (0.64, 0.64, 0.5)
        case "station", "street_gray", "street_black": return (0.76, 0.86, 0.30)
        case "max": return (0.96, 0.70, 0.26)
        default: return (0.84, 0.84, 0.28)
        }
    }

    static func symbolFor(_ d: Dev) -> String {
        switch d.iconKey ?? "" {
        case "lite", "mini": return firstSymbol(["homepod.mini.fill", "hifispeaker.fill"])
        case "station", "street_gray", "street_black": return firstSymbol(["homepod.fill", "hifispeaker.fill"])
        case "max": return firstSymbol(["hifispeaker.2.fill", "hifispeaker.fill"])
        default: return d.symbol
        }
    }

    var body: some View {
        ZStack {
            if let k = d.iconKey, let img = loadIcon(k) {
                Image(nsImage: img).resizable().interpolation(.high).aspectRatio(contentMode: .fit)
                    .saturation(gray ? 0 : 1.2)
                    .shadow(color: Color.black.opacity(0.10), radius: Swift.max(1.5, size * 0.045), x: 0, y: size * 0.035)
            } else if let k = d.iconKey, VP.supports(k) {
                VectorIcon(key: k, size: size, lit: !gray, off: gray)
            } else {
                // нет готовой картинки: аккуратная плашка цвета категории со значком.
                // Станции различаются размером и формой: Лайт — маленький кружок, Мини — побольше,
                // Станция — вытянутая, Макс — самая большая и широкая.
                let tint = catFor(d.cat).tint
                let g = DevImage.geometry(d.iconKey)
                let w = size * g.w, h = size * g.h
                let r = Swift.min(w, h) * g.round
                let plate = RoundedRectangle(cornerRadius: r, style: .continuous)
                plate.fill(LinearGradient(colors: gray ? [Color(white: 0.84), Color(white: 0.70)] : [tint.opacity(0.78), tint],
                                          startPoint: .top, endPoint: .bottom))
                    .overlay(plate.stroke(Color.white.opacity(gray ? 0.3 : 0.45), lineWidth: 0.8))
                    .overlay(
                        // мягкий блик сверху
                        plate.fill(LinearGradient(colors: [Color.white.opacity(0.28), Color.white.opacity(0)], startPoint: .top, endPoint: .center))
                    )
                    .shadow(color: (gray ? Color.black : tint).opacity(gray ? 0.12 : 0.30), radius: Swift.max(2, size * 0.06), x: 0, y: size * 0.04)
                    .frame(width: w, height: h)
                Image(systemName: DevImage.symbolFor(d)).font(.system(size: Swift.min(w, h) * 0.52, weight: .semibold))
                    .foregroundColor(Color.white.opacity(gray ? 0.9 : 1))
            }
        }
        .frame(width: size, height: size)
        .opacity(d.online ? 1 : 0.5)
    }
}

/// нарисованная иконка устройства: набор слоёв с градиентами, координаты в долях клетки
struct VP {
    let k: Int            // 0 — скруглённый прямоугольник, 1 — эллипс
    let cx: CGFloat, cy: CGFloat, w: CGFloat, h: CGFloat, rad: CGFloat
    let dir: Int          // 0 сверху вниз, 1 слева направо, 2 радиальный, 3 по диагонали
    let st: [CGFloat]     // позиция, r, g, b, прозрачность
    var blur: CGFloat = 0
    var lit: Int = 0      // 1 — только включено, 2 — только выключено
    var stroke: CGFloat = 0
    var rot: CGFloat = 0
    var ring: [CGFloat] = []
    var rw: CGFloat = 0.022

    var stops: [Gradient.Stop] {
        var out: [Gradient.Stop] = []
        var i = 0
        while i + 4 < st.count {
            out.append(Gradient.Stop(color: Color(red: st[i + 1] / 255, green: st[i + 2] / 255, blue: st[i + 3] / 255).opacity(Double(st[i + 4])),
                                     location: st[i]))
            i += 5
        }
        return out
    }

    static func layers(_ key: String) -> [VP] {
        var a: [VP] = []
        switch key {
        case "station", "street_black", "music":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.483, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.53, w: 0.46, h: 0.66, rad: 0.06, dir: 1, st: [0, 28, 28, 32, 1, 0.28, 58, 58, 66, 1, 0.55, 90, 90, 100, 1, 0.82, 58, 58, 66, 1, 1, 28, 28, 32, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.83, w: 0.4508, h: 0.07, rad: 0.03, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0.3]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.2, w: 0.46, h: 0.1196, rad: 0, dir: 2, st: [0, 74, 74, 84, 1, 1, 42, 42, 48, 1], stroke: 0.25))
            a.append(VP(k: 1, cx: 0.5, cy: 0.2, w: 0.322, h: 0.0828, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.2, w: 0.3404, h: 0.0874, rad: 0, dir: 0, st: [0, 150, 110, 255, 0, 1, 150, 110, 255, 0], lit: 1, ring: [150, 110, 255]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.2, w: 0.3404, h: 0.0874, rad: 0, dir: 0, st: [0, 110, 110, 118, 0, 1, 110, 110, 118, 0], lit: 2, ring: [105, 105, 112]))
        case "street_gray":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.483, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.53, w: 0.46, h: 0.66, rad: 0.06, dir: 1, st: [0, 110, 110, 118, 1, 0.28, 154, 154, 164, 1, 0.55, 196, 196, 204, 1, 0.82, 154, 154, 164, 1, 1, 110, 110, 118, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.83, w: 0.4508, h: 0.07, rad: 0.03, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0.3]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.2, w: 0.46, h: 0.1196, rad: 0, dir: 2, st: [0, 184, 184, 192, 1, 1, 138, 138, 146, 1], stroke: 0.25))
            a.append(VP(k: 1, cx: 0.5, cy: 0.2, w: 0.322, h: 0.0828, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.2, w: 0.3404, h: 0.0874, rad: 0, dir: 0, st: [0, 150, 110, 255, 0, 1, 150, 110, 255, 0], lit: 1, ring: [150, 110, 255]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.2, w: 0.3404, h: 0.0874, rad: 0, dir: 0, st: [0, 110, 110, 118, 0, 1, 110, 110, 118, 0], lit: 2, ring: [105, 105, 112]))
        case "mini":
            a.append(VP(k: 1, cx: 0.5, cy: 0.82, w: 0.651, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.65, w: 0.62, h: 0.3, rad: 0.06, dir: 1, st: [0, 122, 125, 132, 1, 0.28, 164, 167, 174, 1, 0.55, 207, 209, 214, 1, 0.82, 164, 167, 174, 1, 1, 122, 125, 132, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.77, w: 0.6076, h: 0.07, rad: 0.03, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0.3]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.62, h: 0.1612, rad: 0, dir: 2, st: [0, 196, 198, 204, 1, 1, 154, 157, 164, 1], stroke: 0.25))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.434, h: 0.1116, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.4588, h: 0.1178, rad: 0, dir: 0, st: [0, 150, 110, 255, 0, 1, 150, 110, 255, 0], lit: 1, ring: [150, 110, 255]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.4588, h: 0.1178, rad: 0, dir: 0, st: [0, 110, 110, 118, 0, 1, 110, 110, 118, 0], lit: 2, ring: [105, 105, 112]))
        case "lite":
            a.append(VP(k: 1, cx: 0.5, cy: 0.84, w: 0.42, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.69, w: 0.4, h: 0.26, rad: 0.06, dir: 1, st: [0, 216, 210, 198, 1, 0.28, 239, 233, 222, 1, 0.55, 255, 250, 240, 1, 0.82, 239, 233, 222, 1, 1, 216, 210, 198, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.79, w: 0.392, h: 0.07, rad: 0.03, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0.3]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.56, w: 0.4, h: 0.104, rad: 0, dir: 2, st: [0, 255, 250, 240, 1, 1, 227, 220, 208, 1], stroke: 0.25))
            a.append(VP(k: 1, cx: 0.5, cy: 0.56, w: 0.28, h: 0.072, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.56, w: 0.296, h: 0.076, rad: 0, dir: 0, st: [0, 150, 110, 255, 0, 1, 150, 110, 255, 0], lit: 1, ring: [150, 110, 255]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.56, w: 0.296, h: 0.076, rad: 0, dir: 0, st: [0, 110, 110, 118, 0, 1, 110, 110, 118, 0], lit: 2, ring: [105, 105, 112]))
        case "max":
            a.append(VP(k: 1, cx: 0.5, cy: 0.8, w: 0.95, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.56, w: 0.92, h: 0.4, rad: 0.12, dir: 1, st: [0, 20, 20, 24, 1, 0.28, 46, 46, 54, 1, 0.55, 74, 74, 84, 1, 0.82, 46, 46, 54, 1, 1, 20, 20, 24, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.41, w: 0.8924, h: 0.1, rad: 0.05, dir: 0, st: [0, 255, 255, 255, 0.22, 1, 255, 255, 255, 0]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.73, w: 0.8832, h: 0.08, rad: 0.04, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0.35]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.49, w: 0.5704, h: 0.035, rad: 0.0175, dir: 1, st: [0, 150, 110, 255, 0, 0.5, 170, 130, 255, 1, 1, 150, 110, 255, 0], blur: 0.004, lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.49, w: 0.5704, h: 0.03, rad: 0.015, dir: 1, st: [0, 120, 120, 128, 0, 0.5, 120, 120, 128, 0.8, 1, 120, 120, 128, 0], lit: 2))
            a.append(VP(k: 1, cx: 0.5, cy: 0.63, w: 0.16, h: 0.16, rad: 0, dir: 2, st: [0, 70, 70, 80, 1, 1, 30, 30, 36, 1], stroke: 0.2))
        case "bulb":
            a.append(VP(k: 1, cx: 0.5, cy: 0.9, w: 0.34, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.36, w: 0.78, h: 0.78, rad: 0, dir: 2, st: [0, 255, 214, 120, 0.55, 1, 255, 214, 120, 0], blur: 0.04, lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.36, w: 0.5, h: 0.5, rad: 0, dir: 2, st: [0, 255, 252, 225, 1, 0.55, 255, 224, 130, 1, 1, 255, 176, 60, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.36, w: 0.5, h: 0.5, rad: 0, dir: 2, st: [0, 250, 251, 253, 1, 0.6, 226, 230, 238, 1, 1, 188, 194, 206, 1], lit: 2, stroke: 0.5))
            a.append(VP(k: 1, cx: 0.42, cy: 0.26, w: 0.16, h: 0.1, rad: 0, dir: 0, st: [0, 255, 255, 255, 0.85, 1, 255, 255, 255, 0]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.64, w: 0.26, h: 0.14, rad: 0.04, dir: 0, st: [0, 223, 226, 232, 1, 1, 185, 190, 200, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.74, w: 0.26, h: 0.12, rad: 0.03, dir: 1, st: [0, 140, 145, 156, 1, 0.28, 214, 217, 224, 1, 0.55, 244, 245, 248, 1, 0.82, 214, 217, 224, 1, 1, 140, 145, 156, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.72, w: 0.26, h: 0.012, rad: 0.006, dir: 1, st: [0, 0, 0, 0, 0.25, 1, 0, 0, 0, 0.25]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.76, w: 0.26, h: 0.012, rad: 0.006, dir: 1, st: [0, 0, 0, 0, 0.25, 1, 0, 0, 0, 0.25]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.83, w: 0.12, h: 0.05, rad: 0.025, dir: 0, st: [0, 74, 77, 86, 1, 1, 42, 44, 50, 1]))
        case "lamp_white":
            a.append(VP(k: 1, cx: 0.5, cy: 0.9, w: 0.5, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.46, h: 0.07, rad: 0, dir: 2, st: [0, 91, 95, 106, 1, 1, 45, 48, 54, 1], stroke: 0.2))
            a.append(VP(k: 0, cx: 0.5, cy: 0.6, w: 0.045, h: 0.5, rad: 0.02, dir: 1, st: [0, 125, 130, 142, 1, 0.28, 201, 204, 212, 1, 0.55, 236, 238, 242, 1, 0.82, 201, 204, 212, 1, 1, 125, 130, 142, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.6, h: 0.5, rad: 0, dir: 2, st: [0, 255, 220, 140, 0.5, 1, 255, 220, 140, 0], blur: 0.04, lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.56, h: 0.3, rad: 0.14, dir: 1, st: [0, 220, 223, 230, 1, 0.3, 251, 251, 253, 1, 0.7, 251, 251, 253, 1, 1, 220, 223, 230, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.5, cy: 0.43, w: 0.4, h: 0.07, rad: 0, dir: 0, st: [0, 255, 236, 180, 1, 1, 255, 200, 110, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.43, w: 0.4, h: 0.07, rad: 0, dir: 0, st: [0, 213, 216, 223, 1, 1, 180, 185, 196, 1], lit: 2))
        case "lamp_pink":
            a.append(VP(k: 1, cx: 0.5, cy: 0.9, w: 0.5, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.46, h: 0.07, rad: 0, dir: 2, st: [0, 91, 95, 106, 1, 1, 45, 48, 54, 1], stroke: 0.2))
            a.append(VP(k: 0, cx: 0.5, cy: 0.6, w: 0.045, h: 0.5, rad: 0.02, dir: 1, st: [0, 125, 130, 142, 1, 0.28, 201, 204, 212, 1, 0.55, 236, 238, 242, 1, 0.82, 201, 204, 212, 1, 1, 125, 130, 142, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.6, h: 0.5, rad: 0, dir: 2, st: [0, 255, 150, 190, 0.5, 1, 255, 150, 190, 0], blur: 0.04, lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.56, h: 0.3, rad: 0.14, dir: 1, st: [0, 229, 188, 203, 1, 0.3, 249, 230, 238, 1, 0.7, 249, 230, 238, 1, 1, 229, 188, 203, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.5, cy: 0.43, w: 0.4, h: 0.07, rad: 0, dir: 0, st: [0, 255, 236, 180, 1, 1, 255, 200, 110, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.43, w: 0.4, h: 0.07, rad: 0, dir: 0, st: [0, 213, 216, 223, 1, 1, 180, 185, 196, 1], lit: 2))
        case "lamp_ambi":
            a.append(VP(k: 1, cx: 0.5, cy: 0.9, w: 0.5, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.46, h: 0.07, rad: 0, dir: 2, st: [0, 91, 95, 106, 1, 1, 45, 48, 54, 1], stroke: 0.2))
            a.append(VP(k: 0, cx: 0.5, cy: 0.6, w: 0.045, h: 0.5, rad: 0.02, dir: 1, st: [0, 125, 130, 142, 1, 0.28, 201, 204, 212, 1, 0.55, 236, 238, 242, 1, 0.82, 201, 204, 212, 1, 1, 125, 130, 142, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.6, h: 0.5, rad: 0, dir: 2, st: [0, 190, 150, 255, 0.5, 1, 190, 150, 255, 0], blur: 0.04, lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.56, h: 0.3, rad: 0.14, dir: 1, st: [0, 214, 200, 240, 1, 0.3, 244, 236, 255, 1, 0.7, 244, 236, 255, 1, 1, 214, 200, 240, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.5, cy: 0.43, w: 0.4, h: 0.07, rad: 0, dir: 0, st: [0, 255, 236, 180, 1, 1, 255, 200, 110, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.43, w: 0.4, h: 0.07, rad: 0, dir: 0, st: [0, 213, 216, 223, 1, 1, 180, 185, 196, 1], lit: 2))
        case "strip":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.86, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.55, w: 0.98, h: 0.6, rad: 0, dir: 2, st: [0, 255, 225, 140, 0.45, 1, 255, 225, 140, 0], blur: 0.05, lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.645, w: 0.9, h: 0.42, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0], ring: [176, 181, 194], rw: 0.085))
            a.append(VP(k: 1, cx: 0.5, cy: 0.62, w: 0.9, h: 0.42, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0], ring: [246, 247, 250], rw: 0.085))
            a.append(VP(k: 1, cx: 0.5, cy: 0.608, w: 0.9, h: 0.42, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0], ring: [255, 255, 255], rw: 0.03))
            a.append(VP(k: 1, cx: 0.928, cy: 0.6849, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.928, cy: 0.6849, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.8641, cy: 0.7434, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.8641, cy: 0.7434, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.7645, cy: 0.7899, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.7645, cy: 0.7899, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.6391, cy: 0.8197, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.6391, cy: 0.8197, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.5, cy: 0.83, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.83, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.3609, cy: 0.8197, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.3609, cy: 0.8197, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.2355, cy: 0.7899, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.2355, cy: 0.7899, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.1359, cy: 0.7434, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.1359, cy: 0.7434, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.072, cy: 0.6849, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.072, cy: 0.6849, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.5, cy: 0.525, w: 0.78, h: 0.35, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0], ring: [176, 181, 194], rw: 0.085))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.78, h: 0.35, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0], ring: [246, 247, 250], rw: 0.085))
            a.append(VP(k: 1, cx: 0.5, cy: 0.488, w: 0.78, h: 0.35, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0], ring: [255, 255, 255], rw: 0.03))
            a.append(VP(k: 1, cx: 0.8709, cy: 0.5541, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.8709, cy: 0.5541, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.8155, cy: 0.6029, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.8155, cy: 0.6029, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.7292, cy: 0.6416, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.7292, cy: 0.6416, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.6205, cy: 0.6664, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.6205, cy: 0.6664, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.5, cy: 0.675, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.675, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.3795, cy: 0.6664, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.3795, cy: 0.6664, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.2708, cy: 0.6416, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.2708, cy: 0.6416, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.1845, cy: 0.6029, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.1845, cy: 0.6029, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.1291, cy: 0.5541, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.1291, cy: 0.5541, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.5, cy: 0.405, w: 0.64, h: 0.28, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0], ring: [176, 181, 194], rw: 0.085))
            a.append(VP(k: 1, cx: 0.5, cy: 0.38, w: 0.64, h: 0.28, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0], ring: [246, 247, 250], rw: 0.085))
            a.append(VP(k: 1, cx: 0.5, cy: 0.368, w: 0.64, h: 0.28, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0], ring: [255, 255, 255], rw: 0.03))
            a.append(VP(k: 1, cx: 0.8043, cy: 0.4233, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.8043, cy: 0.4233, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.7589, cy: 0.4623, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.7589, cy: 0.4623, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.6881, cy: 0.4933, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.6881, cy: 0.4933, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.5989, cy: 0.5131, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5989, cy: 0.5131, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.5, cy: 0.52, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.52, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.4011, cy: 0.5131, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.4011, cy: 0.5131, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.3119, cy: 0.4933, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.3119, cy: 0.4933, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.2411, cy: 0.4623, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.2411, cy: 0.4623, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.1957, cy: 0.4233, w: 0.034, h: 0.034, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.45, 255, 245, 170, 1, 1, 255, 214, 90, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.1957, cy: 0.4233, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 236, 238, 243, 1, 1, 169, 174, 187, 1], lit: 2))
            a.append(VP(k: 0, cx: 0.8, cy: 0.7, w: 0.1, h: 0.06, rad: 0.015, dir: 0, st: [0, 255, 255, 255, 1, 1, 212, 216, 225, 1], stroke: 0.5))
        case "tv":
            a.append(VP(k: 1, cx: 0.5, cy: 0.86, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.4, w: 0.9, h: 0.56, rad: 0.04, dir: 0, st: [0, 44, 47, 56, 1, 1, 16, 18, 22, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.4, w: 0.85, h: 0.5, rad: 0.025, dir: 3, st: [0, 59, 111, 214, 1, 0.5, 111, 75, 214, 1, 1, 192, 79, 176, 1], lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.4, w: 0.85, h: 0.5, rad: 0.025, dir: 3, st: [0, 29, 32, 40, 1, 1, 10, 11, 14, 1], lit: 2))
            a.append(VP(k: 0, cx: 0.36, cy: 0.3, w: 0.55, h: 0.2, rad: 0.02, dir: 3, st: [0, 255, 255, 255, 0.16, 1, 255, 255, 255, 0]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.73, w: 0.12, h: 0.08, rad: 0.01, dir: 1, st: [0, 58, 61, 70, 1, 0.28, 124, 128, 140, 1, 0.55, 162, 166, 178, 1, 0.82, 124, 128, 140, 1, 1, 58, 61, 70, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.8, w: 0.38, h: 0.045, rad: 0, dir: 0, st: [0, 142, 146, 158, 1, 1, 74, 77, 86, 1]))
        case "kettle":
            a.append(VP(k: 1, cx: 0.5, cy: 0.87, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.83, w: 0.54, h: 0.07, rad: 0.03, dir: 0, st: [0, 42, 44, 50, 1, 1, 18, 19, 22, 1]))
            a.append(VP(k: 0, cx: 0.78, cy: 0.54, w: 0.07, h: 0.34, rad: 0.035, dir: 1, st: [0, 26, 27, 31, 1, 0.28, 58, 60, 68, 1, 0.55, 82, 85, 94, 1, 0.82, 58, 60, 68, 1, 1, 26, 27, 31, 1]))
            a.append(VP(k: 0, cx: 0.46, cy: 0.54, w: 0.46, h: 0.56, rad: 0.13, dir: 1, st: [0, 154, 160, 172, 1, 0.28, 230, 232, 238, 1, 0.55, 255, 255, 255, 1, 0.82, 230, 232, 238, 1, 1, 154, 160, 172, 1], stroke: 0.4))
            a.append(VP(k: 0, cx: 0.46, cy: 0.3, w: 0.34, h: 0.07, rad: 0.03, dir: 1, st: [0, 43, 45, 51, 1, 0.28, 74, 77, 86, 1, 0.55, 106, 110, 120, 1, 0.82, 74, 77, 86, 1, 1, 43, 45, 51, 1]))
            a.append(VP(k: 1, cx: 0.46, cy: 0.255, w: 0.08, h: 0.05, rad: 0, dir: 2, st: [0, 85, 88, 95, 1, 1, 36, 38, 43, 1]))
            a.append(VP(k: 0, cx: 0.36, cy: 0.58, w: 0.045, h: 0.3, rad: 0.022, dir: 0, st: [0, 120, 200, 255, 0.85, 1, 70, 150, 230, 0.85], lit: 1))
            a.append(VP(k: 0, cx: 0.36, cy: 0.58, w: 0.045, h: 0.3, rad: 0.022, dir: 0, st: [0, 150, 170, 190, 0.5, 1, 110, 130, 150, 0.5], lit: 2))
            a.append(VP(k: 1, cx: 0.4, cy: 0.45, w: 0.1, h: 0.22, rad: 0, dir: 0, st: [0, 255, 255, 255, 0.55, 1, 255, 255, 255, 0]))
        case "ac":
            a.append(VP(k: 1, cx: 0.5, cy: 0.74, w: 0.86, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.42, w: 0.92, h: 0.36, rad: 0.09, dir: 0, st: [0, 255, 255, 255, 1, 1, 217, 221, 229, 1], stroke: 0.6))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.88, h: 0.08, rad: 0.04, dir: 0, st: [0, 255, 255, 255, 0.9, 1, 255, 255, 255, 0]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.53, w: 0.8, h: 0.07, rad: 0.03, dir: 0, st: [0, 86, 90, 102, 1, 1, 43, 45, 52, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.59, w: 0.76, h: 0.025, rad: 0.012, dir: 0, st: [0, 182, 187, 199, 1, 1, 138, 143, 156, 1]))
            a.append(VP(k: 1, cx: 0.84, cy: 0.35, w: 0.04, h: 0.04, rad: 0, dir: 2, st: [0, 150, 255, 190, 1, 1, 40, 200, 110, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.84, cy: 0.35, w: 0.04, h: 0.04, rad: 0, dir: 2, st: [0, 180, 185, 196, 1, 1, 143, 148, 161, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.5, cy: 0.78, w: 0.5, h: 0.1, rad: 0, dir: 0, st: [0, 150, 200, 255, 0.45, 1, 150, 200, 255, 0], blur: 0.03, lit: 1))
        case "vacuum":
            a.append(VP(k: 1, cx: 0.5, cy: 0.8, w: 0.74, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.78, h: 0.78, rad: 0, dir: 2, st: [0, 106, 110, 122, 1, 0.6, 58, 61, 70, 1, 1, 28, 29, 34, 1], stroke: 0.3))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.62, h: 0.62, rad: 0, dir: 3, st: [0, 90, 94, 106, 1, 1, 42, 44, 51, 1], stroke: 0.25))
            a.append(VP(k: 1, cx: 0.5, cy: 0.4, w: 0.22, h: 0.22, rad: 0, dir: 2, st: [0, 154, 158, 169, 1, 1, 59, 62, 71, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.5, cy: 0.4, w: 0.1, h: 0.1, rad: 0, dir: 2, st: [0, 42, 44, 51, 1, 1, 14, 15, 18, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.64, w: 0.07, h: 0.07, rad: 0, dir: 2, st: [0, 180, 160, 255, 1, 1, 120, 90, 230, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.64, w: 0.07, h: 0.07, rad: 0, dir: 2, st: [0, 143, 148, 161, 1, 1, 91, 95, 107, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.34, cy: 0.28, w: 0.2, h: 0.1, rad: 0, dir: 0, st: [0, 255, 255, 255, 0.22, 1, 255, 255, 255, 0]))
        case "purifier":
            a.append(VP(k: 1, cx: 0.5, cy: 0.9, w: 0.528, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.44, h: 0.76, rad: 0.12, dir: 1, st: [0, 201, 205, 214, 1, 0.28, 255, 255, 255, 1, 0.55, 255, 255, 255, 1, 0.82, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.16, w: 0.308, h: 0.04, rad: 0.02, dir: 0, st: [0, 157, 162, 174, 1, 1, 201, 205, 214, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.4, w: 0.26, h: 0.025, rad: 0.012, dir: 0, st: [0, 174, 179, 191, 1, 1, 217, 220, 227, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.46, w: 0.26, h: 0.025, rad: 0.012, dir: 0, st: [0, 174, 179, 191, 1, 1, 217, 220, 227, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.52, w: 0.26, h: 0.025, rad: 0.012, dir: 0, st: [0, 174, 179, 191, 1, 1, 217, 220, 227, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.7, w: 0.06, h: 0.06, rad: 0, dir: 2, st: [0, 150, 255, 200, 1, 1, 40, 190, 130, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.7, w: 0.06, h: 0.06, rad: 0, dir: 2, st: [0, 201, 205, 214, 1, 1, 157, 162, 174, 1], lit: 2))
        case "humidifier":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.58, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.14, w: 0.4, h: 0.26, rad: 0, dir: 0, st: [0, 190, 225, 255, 0.7, 1, 190, 225, 255, 0], blur: 0.03, lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.58, w: 0.46, h: 0.62, rad: 0.19, dir: 1, st: [0, 201, 205, 214, 1, 0.28, 255, 255, 255, 1, 0.55, 255, 255, 255, 1, 0.82, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.26, h: 0.05, rad: 0.025, dir: 0, st: [0, 143, 148, 161, 1, 1, 185, 189, 200, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.62, w: 0.07, h: 0.34, rad: 0.035, dir: 0, st: [0, 150, 210, 255, 0.9, 1, 70, 150, 235, 0.9], lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.62, w: 0.07, h: 0.34, rad: 0.035, dir: 0, st: [0, 200, 205, 215, 0.9, 1, 170, 176, 190, 0.9], lit: 2))
            a.append(VP(k: 1, cx: 0.5, cy: 0.8, w: 0.07, h: 0.03, rad: 0, dir: 2, st: [0, 157, 162, 174, 1, 1, 124, 129, 142, 1]))
        case "switch2":
            a.append(VP(k: 1, cx: 0.5, cy: 0.84, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.66, h: 0.66, rad: 0.12, dir: 3, st: [0, 255, 255, 255, 1, 1, 217, 221, 229, 1], stroke: 0.7))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.5, h: 0.5, rad: 0.08, dir: 3, st: [0, 243, 245, 249, 1, 1, 221, 225, 233, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.5, h: 0.012, rad: 0.006, dir: 1, st: [0, 0, 0, 0, 0.12, 1, 0, 0, 0, 0.12]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.07, h: 0.07, rad: 0, dir: 2, st: [0, 180, 160, 255, 1, 1, 120, 90, 230, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.05, h: 0.05, rad: 0, dir: 2, st: [0, 196, 200, 210, 1, 1, 157, 162, 174, 1], lit: 2))
        case "ir":
            a.append(VP(k: 1, cx: 0.5, cy: 0.84, w: 0.8, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.64, w: 0.74, h: 0.34, rad: 0.17, dir: 1, st: [0, 174, 179, 190, 1, 0.28, 230, 233, 239, 1, 0.55, 255, 255, 255, 1, 0.82, 230, 233, 239, 1, 1, 174, 179, 190, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.47, w: 0.76, h: 0.3, rad: 0.15, dir: 1, st: [0, 18, 19, 23, 1, 0.28, 43, 45, 52, 1, 0.55, 69, 72, 81, 1, 0.82, 43, 45, 52, 1, 1, 18, 19, 23, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.595, w: 0.72, h: 0.022, rad: 0.011, dir: 0, st: [0, 0, 0, 0, 0.4, 1, 0, 0, 0, 0.05]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.385, w: 0.62, h: 0.23, rad: 0, dir: 2, st: [0, 106, 109, 118, 1, 0.55, 60, 62, 70, 1, 1, 32, 33, 38, 1], stroke: 0.18))
            a.append(VP(k: 1, cx: 0.38, cy: 0.32, w: 0.22, h: 0.06, rad: 0, dir: 0, st: [0, 255, 255, 255, 0.22, 1, 255, 255, 255, 0]))
            a.append(VP(k: 0, cx: 0.3, cy: 0.715, w: 0.1, h: 0.042, rad: 0.021, dir: 0, st: [0, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.46, cy: 0.715, w: 0.028, h: 0.028, rad: 0, dir: 2, st: [0, 200, 185, 255, 1, 1, 130, 100, 235, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.46, cy: 0.715, w: 0.026, h: 0.026, rad: 0, dir: 2, st: [0, 143, 148, 161, 1, 1, 74, 77, 86, 1], lit: 2))
        case "midi":
            a.append(VP(k: 1, cx: 0.5, cy: 0.78, w: 0.567, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.53, w: 0.54, h: 0.46, rad: 0.06, dir: 1, st: [0, 42, 42, 48, 1, 0.28, 74, 74, 84, 1, 0.55, 108, 108, 120, 1, 0.82, 74, 74, 84, 1, 1, 42, 42, 48, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.73, w: 0.5292, h: 0.07, rad: 0.03, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0.3]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.3, w: 0.54, h: 0.1404, rad: 0, dir: 2, st: [0, 90, 90, 100, 1, 1, 52, 52, 60, 1], stroke: 0.25))
            a.append(VP(k: 1, cx: 0.5, cy: 0.3, w: 0.378, h: 0.0972, rad: 0, dir: 0, st: [0, 0, 0, 0, 0, 1, 0, 0, 0, 0]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.3, w: 0.3996, h: 0.1026, rad: 0, dir: 0, st: [0, 150, 110, 255, 0, 1, 150, 110, 255, 0], lit: 1, ring: [150, 110, 255]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.3, w: 0.3996, h: 0.1026, rad: 0, dir: 0, st: [0, 110, 110, 118, 0, 1, 110, 110, 118, 0], lit: 2, ring: [105, 105, 112]))
        case "socket":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.6, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.58, h: 0.62, rad: 0.12, dir: 3, st: [0, 255, 255, 255, 1, 1, 212, 216, 225, 1], stroke: 0.7))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.46, h: 0.5, rad: 0.09, dir: 3, st: [0, 241, 243, 248, 1, 1, 221, 225, 233, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.3, h: 0.3, rad: 0, dir: 2, st: [0, 217, 220, 227, 1, 1, 185, 189, 200, 1]))
            a.append(VP(k: 1, cx: 0.42, cy: 0.5, w: 0.055, h: 0.055, rad: 0, dir: 2, st: [0, 58, 61, 70, 1, 1, 21, 22, 26, 1]))
            a.append(VP(k: 1, cx: 0.58, cy: 0.5, w: 0.055, h: 0.055, rad: 0, dir: 2, st: [0, 58, 61, 70, 1, 1, 21, 22, 26, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.7, w: 0.1, h: 0.025, rad: 0.012, dir: 0, st: [0, 195, 199, 209, 1, 1, 165, 170, 182, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.28, w: 0.05, h: 0.05, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.5, 150, 255, 200, 1, 1, 90, 153, 120, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.28, w: 0.045, h: 0.045, rad: 0, dir: 2, st: [0, 213, 216, 223, 1, 1, 157, 162, 174, 1], lit: 2))
        case "ceiling":
            a.append(VP(k: 1, cx: 0.5, cy: 0.8, w: 0.7, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.2, w: 0.8, h: 0.3, rad: 0, dir: 2, st: [0, 246, 247, 250, 1, 1, 201, 205, 214, 1], stroke: 0.5))
            a.append(VP(k: 1, cx: 0.5, cy: 0.28, w: 0.7, h: 0.16, rad: 0, dir: 0, st: [0, 255, 236, 180, 0, 1, 255, 236, 180, 0]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.34, w: 0.78, h: 0.2, rad: 0.1, dir: 0, st: [0, 255, 255, 255, 1, 1, 211, 215, 224, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.5, cy: 0.58, w: 0.74, h: 0.26, rad: 0, dir: 2, st: [0, 255, 236, 170, 0.85, 0.6, 255, 214, 120, 0.35, 1, 255, 214, 120, 0], blur: 0.03, lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.46, w: 0.6, h: 0.12, rad: 0, dir: 0, st: [0, 255, 250, 225, 1, 1, 255, 220, 140, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.46, w: 0.6, h: 0.12, rad: 0, dir: 0, st: [0, 236, 238, 243, 1, 1, 201, 205, 214, 1], lit: 2))
        case "floorlamp":
            a.append(VP(k: 1, cx: 0.5, cy: 0.92, w: 0.5, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.91, w: 0.4, h: 0.06, rad: 0, dir: 2, st: [0, 91, 95, 106, 1, 1, 45, 48, 54, 1], stroke: 0.2))
            a.append(VP(k: 0, cx: 0.5, cy: 0.6, w: 0.04, h: 0.62, rad: 0.02, dir: 1, st: [0, 125, 130, 142, 1, 0.28, 201, 204, 212, 1, 0.55, 236, 238, 242, 1, 0.82, 201, 204, 212, 1, 1, 125, 130, 142, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.38, w: 0.62, h: 0.52, rad: 0, dir: 2, st: [0, 255, 220, 140, 0.5, 1, 255, 220, 140, 0], blur: 0.04, lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.22, w: 0.46, h: 0.3, rad: 0.07, dir: 1, st: [0, 217, 211, 198, 1, 0.35, 255, 250, 240, 1, 0.7, 255, 250, 240, 1, 1, 217, 211, 198, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.5, cy: 0.36, w: 0.46, h: 0.07, rad: 0, dir: 0, st: [0, 255, 236, 180, 1, 1, 255, 200, 110, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.36, w: 0.46, h: 0.07, rad: 0, dir: 0, st: [0, 213, 216, 223, 1, 1, 180, 185, 196, 1], lit: 2))
        case "fan":
            a.append(VP(k: 1, cx: 0.5, cy: 0.9, w: 0.5, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.86, w: 0.14, h: 0.07, rad: 0.03, dir: 0, st: [0, 143, 148, 161, 1, 1, 91, 95, 107, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.74, w: 0.05, h: 0.22, rad: 0.02, dir: 1, st: [0, 125, 130, 142, 1, 0.28, 201, 204, 212, 1, 0.55, 236, 238, 242, 1, 0.82, 201, 204, 212, 1, 1, 125, 130, 142, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.42, w: 0.74, h: 0.74, rad: 0, dir: 2, st: [0, 243, 245, 249, 1, 1, 195, 199, 209, 1], stroke: 0.5))
            a.append(VP(k: 1, cx: 0.5, cy: 0.42, w: 0.66, h: 0.66, rad: 0, dir: 2, st: [0, 233, 236, 242, 1, 1, 185, 189, 200, 1]))
            a.append(VP(k: 1, cx: 0.6299, cy: 0.375, w: 0.3, h: 0.15, rad: 0, dir: 0, st: [0, 255, 255, 255, 1, 1, 195, 199, 209, 1], stroke: 0.5, rot: -30))
            a.append(VP(k: 1, cx: 0.5, cy: 0.6, w: 0.3, h: 0.15, rad: 0, dir: 0, st: [0, 255, 255, 255, 1, 1, 195, 199, 209, 1], stroke: 0.5, rot: 90))
            a.append(VP(k: 1, cx: 0.3701, cy: 0.375, w: 0.3, h: 0.15, rad: 0, dir: 0, st: [0, 255, 255, 255, 1, 1, 195, 199, 209, 1], stroke: 0.5, rot: 210))
            a.append(VP(k: 1, cx: 0.5, cy: 0.42, w: 0.12, h: 0.12, rad: 0, dir: 2, st: [0, 143, 148, 161, 1, 1, 91, 95, 107, 1], stroke: 0.4))
        case "heater":
            a.append(VP(k: 1, cx: 0.5, cy: 0.86, w: 0.8, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.2, cy: 0.46, w: 0.085, h: 0.58, rad: 0.04, dir: 1, st: [0, 185, 189, 200, 1, 0.28, 255, 255, 255, 1, 0.55, 255, 255, 255, 1, 0.82, 255, 255, 255, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.32, cy: 0.46, w: 0.085, h: 0.58, rad: 0.04, dir: 1, st: [0, 185, 189, 200, 1, 0.28, 255, 255, 255, 1, 0.55, 255, 255, 255, 1, 0.82, 255, 255, 255, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.44, cy: 0.46, w: 0.085, h: 0.58, rad: 0.04, dir: 1, st: [0, 185, 189, 200, 1, 0.28, 255, 255, 255, 1, 0.55, 255, 255, 255, 1, 0.82, 255, 255, 255, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.56, cy: 0.46, w: 0.085, h: 0.58, rad: 0.04, dir: 1, st: [0, 185, 189, 200, 1, 0.28, 255, 255, 255, 1, 0.55, 255, 255, 255, 1, 0.82, 255, 255, 255, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.68, cy: 0.46, w: 0.085, h: 0.58, rad: 0.04, dir: 1, st: [0, 185, 189, 200, 1, 0.28, 255, 255, 255, 1, 0.55, 255, 255, 255, 1, 0.82, 255, 255, 255, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.8, cy: 0.46, w: 0.085, h: 0.58, rad: 0.04, dir: 1, st: [0, 185, 189, 200, 1, 0.28, 255, 255, 255, 1, 0.55, 255, 255, 255, 1, 0.82, 255, 255, 255, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.18, w: 0.78, h: 0.07, rad: 0.03, dir: 0, st: [0, 201, 205, 214, 1, 1, 157, 162, 174, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.76, w: 0.78, h: 0.06, rad: 0.03, dir: 0, st: [0, 157, 162, 174, 1, 1, 124, 129, 142, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.7, h: 0.4, rad: 0, dir: 2, st: [0, 255, 150, 80, 0.4, 1, 255, 150, 80, 0], blur: 0.04, lit: 1))
            a.append(VP(k: 1, cx: 0.84, cy: 0.22, w: 0.045, h: 0.045, rad: 0, dir: 2, st: [0, 255, 200, 150, 1, 1, 255, 110, 50, 1], lit: 1))
        case "coffee":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.66, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.58, h: 0.72, rad: 0.08, dir: 1, st: [0, 21, 22, 26, 1, 0.28, 46, 48, 56, 1, 0.55, 71, 74, 84, 1, 0.82, 46, 48, 56, 1, 1, 21, 22, 26, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.2, w: 0.58, h: 0.12, rad: 0.05, dir: 0, st: [0, 58, 61, 70, 1, 1, 28, 29, 34, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.34, w: 0.46, h: 0.1, rad: 0.03, dir: 0, st: [0, 157, 162, 174, 1, 1, 91, 95, 107, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.62, w: 0.3, h: 0.22, rad: 0.03, dir: 0, st: [0, 233, 236, 242, 1, 1, 185, 189, 200, 1], stroke: 0.4))
            a.append(VP(k: 0, cx: 0.5, cy: 0.66, w: 0.15, h: 0.12, rad: 0.03, dir: 0, st: [0, 255, 255, 255, 1, 1, 217, 220, 227, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.82, w: 0.58, h: 0.05, rad: 0.02, dir: 0, st: [0, 58, 61, 70, 1, 1, 21, 22, 26, 1]))
            a.append(VP(k: 0, cx: 0.4, cy: 0.42, w: 0.12, h: 0.4, rad: 0.04, dir: 0, st: [0, 255, 255, 255, 0.2, 1, 255, 255, 255, 0]))
            a.append(VP(k: 1, cx: 0.7, cy: 0.2, w: 0.044, h: 0.044, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.5, 255, 190, 110, 1, 1, 153, 114, 66, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.7, cy: 0.2, w: 0.0396, h: 0.0396, rad: 0, dir: 2, st: [0, 213, 216, 223, 1, 1, 157, 162, 174, 1], lit: 2))
        case "multicooker":
            a.append(VP(k: 1, cx: 0.5, cy: 0.86, w: 0.74, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.58, w: 0.66, h: 0.54, rad: 0.16, dir: 1, st: [0, 185, 189, 200, 1, 0.28, 243, 245, 249, 1, 0.55, 255, 255, 255, 1, 0.82, 243, 245, 249, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.34, w: 0.6, h: 0.2, rad: 0.1, dir: 1, st: [0, 46, 48, 56, 1, 0.28, 74, 77, 86, 1, 0.55, 110, 114, 126, 1, 0.82, 74, 77, 86, 1, 1, 46, 48, 56, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.24, w: 0.1, h: 0.05, rad: 0.02, dir: 0, st: [0, 143, 148, 161, 1, 1, 91, 95, 107, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.66, w: 0.3, h: 0.12, rad: 0.03, dir: 0, st: [0, 58, 61, 70, 1, 1, 21, 22, 26, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.66, w: 0.2, h: 0.04, rad: 0.02, dir: 1, st: [0, 150, 255, 200, 0, 0.5, 150, 255, 200, 1, 1, 150, 255, 200, 0], lit: 1))
        case "oven":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.8, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.8, h: 0.76, rad: 0.07, dir: 0, st: [0, 227, 230, 236, 1, 1, 180, 185, 196, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.22, w: 0.72, h: 0.1, rad: 0.03, dir: 0, st: [0, 46, 48, 56, 1, 1, 21, 22, 26, 1]))
            a.append(VP(k: 1, cx: 0.2, cy: 0.22, w: 0.07, h: 0.07, rad: 0, dir: 2, st: [0, 157, 162, 174, 1, 1, 91, 95, 107, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.4, cy: 0.22, w: 0.07, h: 0.07, rad: 0, dir: 2, st: [0, 157, 162, 174, 1, 1, 91, 95, 107, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.6, cy: 0.22, w: 0.07, h: 0.07, rad: 0, dir: 2, st: [0, 157, 162, 174, 1, 1, 91, 95, 107, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.8, cy: 0.22, w: 0.07, h: 0.07, rad: 0, dir: 2, st: [0, 157, 162, 174, 1, 1, 91, 95, 107, 1], stroke: 0.4))
            a.append(VP(k: 0, cx: 0.5, cy: 0.6, w: 0.62, h: 0.38, rad: 0.04, dir: 0, st: [0, 58, 61, 70, 1, 1, 15, 16, 19, 1], stroke: 0.3))
            a.append(VP(k: 0, cx: 0.5, cy: 0.6, w: 0.44, h: 0.22, rad: 0.03, dir: 0, st: [0, 255, 170, 80, 0.55, 1, 255, 110, 40, 0.55], blur: 0.02, lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.45, w: 0.56, h: 0.025, rad: 0.012, dir: 0, st: [0, 201, 205, 214, 1, 1, 143, 148, 161, 1]))
        case "fridge":
            a.append(VP(k: 1, cx: 0.5, cy: 0.92, w: 0.6, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.48, h: 0.86, rad: 0.06, dir: 1, st: [0, 185, 189, 200, 1, 0.28, 245, 246, 249, 1, 0.55, 255, 255, 255, 1, 0.82, 245, 246, 249, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.34, w: 0.46, h: 0.012, rad: 0.006, dir: 1, st: [0, 0, 0, 0, 0.25, 1, 0, 0, 0, 0.25]))
            a.append(VP(k: 0, cx: 0.62, cy: 0.24, w: 0.025, h: 0.12, rad: 0.012, dir: 0, st: [0, 157, 162, 174, 1, 1, 110, 114, 126, 1]))
            a.append(VP(k: 0, cx: 0.62, cy: 0.52, w: 0.025, h: 0.2, rad: 0.012, dir: 0, st: [0, 157, 162, 174, 1, 1, 110, 114, 126, 1]))
            a.append(VP(k: 0, cx: 0.38, cy: 0.4, w: 0.08, h: 0.62, rad: 0.03, dir: 0, st: [0, 255, 255, 255, 0.3, 1, 255, 255, 255, 0]))
        case "tvbox":
            a.append(VP(k: 1, cx: 0.5, cy: 0.66, w: 0.6, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.66, h: 0.2, rad: 0.07, dir: 0, st: [0, 58, 61, 70, 1, 1, 21, 22, 26, 1], stroke: 0.3))
            a.append(VP(k: 0, cx: 0.5, cy: 0.45, w: 0.62, h: 0.06, rad: 0.03, dir: 0, st: [0, 255, 255, 255, 0.22, 1, 255, 255, 255, 0]))
            a.append(VP(k: 1, cx: 0.7, cy: 0.52, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 180, 160, 255, 1, 1, 120, 90, 230, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.7, cy: 0.52, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 110, 114, 126, 1, 1, 58, 61, 70, 1], lit: 2))
        case "soundbar":
            a.append(VP(k: 1, cx: 0.5, cy: 0.68, w: 0.9, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.92, h: 0.2, rad: 0.1, dir: 1, st: [0, 21, 22, 26, 1, 0.28, 44, 46, 54, 1, 0.55, 64, 67, 77, 1, 0.82, 44, 46, 54, 1, 1, 21, 22, 26, 1], stroke: 0.3))
            a.append(VP(k: 0, cx: 0.5, cy: 0.49, w: 0.8, h: 0.1, rad: 0.05, dir: 0, st: [0, 12, 13, 16, 1, 1, 36, 38, 44, 1]))
            a.append(VP(k: 1, cx: 0.14, cy: 0.49, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 85, 88, 95, 1, 1, 36, 38, 44, 1]))
            a.append(VP(k: 1, cx: 0.23, cy: 0.49, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 85, 88, 95, 1, 1, 36, 38, 44, 1]))
            a.append(VP(k: 1, cx: 0.32, cy: 0.49, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 85, 88, 95, 1, 1, 36, 38, 44, 1]))
            a.append(VP(k: 1, cx: 0.41, cy: 0.49, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 85, 88, 95, 1, 1, 36, 38, 44, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.49, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 85, 88, 95, 1, 1, 36, 38, 44, 1]))
            a.append(VP(k: 1, cx: 0.59, cy: 0.49, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 85, 88, 95, 1, 1, 36, 38, 44, 1]))
            a.append(VP(k: 1, cx: 0.68, cy: 0.49, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 85, 88, 95, 1, 1, 36, 38, 44, 1]))
            a.append(VP(k: 1, cx: 0.77, cy: 0.49, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 85, 88, 95, 1, 1, 36, 38, 44, 1]))
            a.append(VP(k: 1, cx: 0.86, cy: 0.49, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 85, 88, 95, 1, 1, 36, 38, 44, 1]))
            a.append(VP(k: 1, cx: 0.88, cy: 0.5, w: 0.032, h: 0.032, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.5, 150, 110, 255, 1, 1, 90, 66, 153, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.88, cy: 0.5, w: 0.0288, h: 0.0288, rad: 0, dir: 2, st: [0, 213, 216, 223, 1, 1, 157, 162, 174, 1], lit: 2))
        case "projector":
            a.append(VP(k: 1, cx: 0.5, cy: 0.74, w: 0.7, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.52, w: 0.8, h: 0.36, rad: 0.12, dir: 0, st: [0, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.36, cy: 0.52, w: 0.24, h: 0.24, rad: 0, dir: 2, st: [0, 74, 77, 86, 1, 1, 13, 14, 17, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.36, cy: 0.52, w: 0.12, h: 0.12, rad: 0, dir: 2, st: [0, 150, 170, 255, 0.9, 1, 60, 70, 180, 0.9]))
            a.append(VP(k: 0, cx: 0.72, cy: 0.46, w: 0.2, h: 0.025, rad: 0.012, dir: 0, st: [0, 174, 179, 191, 1, 1, 217, 220, 227, 1]))
            a.append(VP(k: 0, cx: 0.72, cy: 0.52, w: 0.2, h: 0.025, rad: 0.012, dir: 0, st: [0, 174, 179, 191, 1, 1, 217, 220, 227, 1]))
        case "curtain":
            a.append(VP(k: 0, cx: 0.5, cy: 0.14, w: 0.9, h: 0.045, rad: 0.02, dir: 0, st: [0, 157, 162, 174, 1, 1, 110, 114, 126, 1]))
            a.append(VP(k: 0, cx: 0.27, cy: 0.52, w: 0.4, h: 0.7, rad: 0.03, dir: 1, st: [0, 201, 206, 217, 1, 0.2, 241, 243, 248, 1, 0.35, 201, 206, 217, 1, 0.55, 241, 243, 248, 1, 0.75, 201, 206, 217, 1, 1, 228, 231, 238, 1], stroke: 0.4))
            a.append(VP(k: 0, cx: 0.73, cy: 0.52, w: 0.4, h: 0.7, rad: 0.03, dir: 1, st: [0, 228, 231, 238, 1, 0.25, 201, 206, 217, 1, 0.45, 241, 243, 248, 1, 0.65, 201, 206, 217, 1, 0.8, 241, 243, 248, 1, 1, 201, 206, 217, 1], stroke: 0.4))
            a.append(VP(k: 0, cx: 0.5, cy: 0.52, w: 0.1, h: 0.66, rad: 0.02, dir: 0, st: [0, 150, 200, 255, 0.25, 1, 150, 200, 255, 0.05], lit: 1))
        case "valve":
            a.append(VP(k: 1, cx: 0.5, cy: 0.84, w: 0.7, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.62, w: 0.86, h: 0.2, rad: 0.05, dir: 0, st: [0, 201, 206, 217, 1, 0.5, 143, 148, 161, 1, 1, 91, 95, 107, 1]))
            a.append(VP(k: 0, cx: 0.18, cy: 0.62, w: 0.1, h: 0.3, rad: 0.03, dir: 0, st: [0, 180, 185, 196, 1, 1, 110, 114, 126, 1]))
            a.append(VP(k: 0, cx: 0.82, cy: 0.62, w: 0.1, h: 0.3, rad: 0.03, dir: 0, st: [0, 180, 185, 196, 1, 1, 110, 114, 126, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.42, w: 0.2, h: 0.22, rad: 0.05, dir: 1, st: [0, 124, 129, 142, 1, 0.28, 208, 211, 219, 1, 0.55, 240, 241, 245, 1, 0.82, 208, 211, 219, 1, 1, 124, 129, 142, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.28, w: 0.07, h: 0.14, rad: 0.02, dir: 1, st: [0, 143, 148, 161, 1, 0.28, 201, 204, 212, 1, 0.55, 233, 235, 240, 1, 0.82, 201, 204, 212, 1, 1, 143, 148, 161, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.2, w: 0.46, h: 0.07, rad: 0.035, dir: 0, st: [0, 255, 110, 110, 1, 1, 200, 50, 60, 1], lit: 2))
            a.append(VP(k: 0, cx: 0.5, cy: 0.2, w: 0.46, h: 0.07, rad: 0.035, dir: 0, st: [0, 110, 200, 255, 1, 1, 40, 130, 220, 1], lit: 1))
        case "gate":
            a.append(VP(k: 1, cx: 0.5, cy: 0.86, w: 0.9, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.88, h: 0.7, rad: 0.04, dir: 0, st: [0, 255, 255, 255, 1, 1, 223, 226, 234, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.24, w: 0.8, h: 0.012, rad: 0.006, dir: 1, st: [0, 0, 0, 0, 0.22, 1, 0, 0, 0, 0.22]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.38, w: 0.8, h: 0.012, rad: 0.006, dir: 1, st: [0, 0, 0, 0, 0.22, 1, 0, 0, 0, 0.22]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.52, w: 0.8, h: 0.012, rad: 0.006, dir: 1, st: [0, 0, 0, 0, 0.22, 1, 0, 0, 0, 0.22]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.66, w: 0.8, h: 0.012, rad: 0.006, dir: 1, st: [0, 0, 0, 0, 0.22, 1, 0, 0, 0, 0.22]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.8, h: 0.1, rad: 0.02, dir: 0, st: [0, 255, 255, 255, 0, 1, 255, 255, 255, 0]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.12, h: 0.025, rad: 0.012, dir: 0, st: [0, 143, 148, 161, 1, 1, 91, 95, 107, 1]))
        case "lock":
            a.append(VP(k: 1, cx: 0.5, cy: 0.86, w: 0.56, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.34, h: 0.34, rad: 0.17, dir: 0, st: [0, 180, 185, 196, 1, 1, 110, 114, 126, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.34, w: 0.2, h: 0.3, rad: 0.1, dir: 0, st: [0, 235, 236, 240, 1, 1, 235, 236, 240, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.6, w: 0.56, h: 0.44, rad: 0.08, dir: 0, st: [0, 74, 77, 86, 1, 1, 28, 29, 34, 1], stroke: 0.3))
            a.append(VP(k: 0, cx: 0.5, cy: 0.52, w: 0.5, h: 0.06, rad: 0.03, dir: 0, st: [0, 255, 255, 255, 0.2, 1, 255, 255, 255, 0]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.58, w: 0.1, h: 0.1, rad: 0, dir: 2, st: [0, 227, 230, 236, 1, 1, 157, 162, 174, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.66, w: 0.04, h: 0.1, rad: 0.02, dir: 0, st: [0, 227, 230, 236, 1, 1, 157, 162, 174, 1]))
        case "washer":
            a.append(VP(k: 1, cx: 0.5, cy: 0.9, w: 0.74, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.72, h: 0.82, rad: 0.07, dir: 1, st: [0, 185, 189, 200, 1, 0.28, 245, 246, 249, 1, 0.55, 255, 255, 255, 1, 0.82, 245, 246, 249, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.2, w: 0.66, h: 0.1, rad: 0.03, dir: 0, st: [0, 223, 226, 234, 1, 1, 180, 185, 196, 1]))
            a.append(VP(k: 1, cx: 0.3, cy: 0.2, w: 0.06, h: 0.06, rad: 0, dir: 2, st: [0, 143, 148, 161, 1, 1, 91, 95, 107, 1]))
            a.append(VP(k: 1, cx: 0.46, cy: 0.2, w: 0.06, h: 0.06, rad: 0, dir: 2, st: [0, 143, 148, 161, 1, 1, 91, 95, 107, 1]))
            a.append(VP(k: 0, cx: 0.7, cy: 0.2, w: 0.12, h: 0.04, rad: 0.02, dir: 0, st: [0, 21, 22, 26, 1, 1, 58, 61, 70, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.58, w: 0.46, h: 0.46, rad: 0, dir: 2, st: [0, 143, 148, 161, 1, 1, 228, 230, 236, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.5, cy: 0.58, w: 0.36, h: 0.36, rad: 0, dir: 2, st: [0, 29, 58, 92, 1, 1, 11, 22, 36, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.64, w: 0.3, h: 0.18, rad: 0, dir: 0, st: [0, 110, 190, 255, 0.55, 1, 60, 140, 230, 0.55], lit: 1))
            a.append(VP(k: 1, cx: 0.42, cy: 0.5, w: 0.1, h: 0.07, rad: 0, dir: 0, st: [0, 255, 255, 255, 0.45, 1, 255, 255, 255, 0]))
        case "dishwasher":
            a.append(VP(k: 1, cx: 0.5, cy: 0.9, w: 0.74, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.72, h: 0.82, rad: 0.07, dir: 0, st: [0, 227, 230, 236, 1, 1, 180, 185, 196, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.18, w: 0.66, h: 0.1, rad: 0.03, dir: 0, st: [0, 46, 48, 56, 1, 1, 21, 22, 26, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.48, w: 0.62, h: 0.04, rad: 0.02, dir: 0, st: [0, 157, 162, 174, 1, 1, 110, 114, 126, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.62, w: 0.6, h: 0.3, rad: 0.03, dir: 0, st: [0, 255, 255, 255, 0.18, 1, 255, 255, 255, 0]))
            a.append(VP(k: 1, cx: 0.7, cy: 0.18, w: 0.04, h: 0.04, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.5, 110, 200, 255, 1, 1, 66, 120, 153, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.7, cy: 0.18, w: 0.036, h: 0.036, rad: 0, dir: 2, st: [0, 213, 216, 223, 1, 1, 157, 162, 174, 1], lit: 2))
            a.append(VP(k: 1, cx: 0.3, cy: 0.18, w: 0.025, h: 0.025, rad: 0, dir: 2, st: [0, 143, 148, 161, 1, 1, 91, 95, 107, 1]))
            a.append(VP(k: 1, cx: 0.36, cy: 0.18, w: 0.025, h: 0.025, rad: 0, dir: 2, st: [0, 143, 148, 161, 1, 1, 91, 95, 107, 1]))
            a.append(VP(k: 1, cx: 0.42, cy: 0.18, w: 0.025, h: 0.025, rad: 0, dir: 2, st: [0, 143, 148, 161, 1, 1, 91, 95, 107, 1]))
        case "iron":
            a.append(VP(k: 1, cx: 0.5, cy: 0.8, w: 0.8, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.7, w: 0.82, h: 0.09, rad: 0.04, dir: 0, st: [0, 233, 236, 242, 1, 1, 143, 148, 161, 1]))
            a.append(VP(k: 0, cx: 0.48, cy: 0.57, w: 0.7, h: 0.24, rad: 0.12, dir: 0, st: [0, 255, 255, 255, 1, 1, 195, 199, 209, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.36, cy: 0.5, w: 0.06, h: 0.05, rad: 0.025, dir: 0, st: [0, 255, 255, 255, 0.7, 1, 255, 255, 255, 0]))
            a.append(VP(k: 0, cx: 0.4, cy: 0.3, w: 0.04, h: 0.12, rad: 0.02, dir: 0, st: [0, 58, 61, 70, 1, 1, 21, 22, 26, 1]))
            a.append(VP(k: 0, cx: 0.64, cy: 0.34, w: 0.04, h: 0.18, rad: 0.02, dir: 0, st: [0, 58, 61, 70, 1, 1, 21, 22, 26, 1]))
            a.append(VP(k: 0, cx: 0.52, cy: 0.25, w: 0.3, h: 0.06, rad: 0.03, dir: 0, st: [0, 74, 77, 86, 1, 1, 21, 22, 26, 1]))
            a.append(VP(k: 1, cx: 0.28, cy: 0.58, w: 0.05, h: 0.05, rad: 0, dir: 2, st: [0, 255, 190, 110, 1, 1, 230, 100, 40, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.28, cy: 0.58, w: 0.05, h: 0.05, rad: 0, dir: 2, st: [0, 157, 162, 174, 1, 1, 110, 114, 126, 1], lit: 2))
        case "s_motion":
            a.append(VP(k: 1, cx: 0.5, cy: 0.82, w: 0.5, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.54, h: 0.54, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.44, h: 0.44, rad: 0, dir: 3, st: [0, 244, 246, 250, 1, 1, 217, 220, 227, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.5, cy: 0.46, w: 0.24, h: 0.24, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.6, 223, 226, 234, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 1, cx: 0.45, cy: 0.4, w: 0.08, h: 0.06, rad: 0, dir: 0, st: [0, 255, 255, 255, 0.8, 1, 255, 255, 255, 0]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.7, w: 0.044, h: 0.044, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.5, 255, 120, 120, 1, 1, 153, 72, 72, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.7, w: 0.0396, h: 0.0396, rad: 0, dir: 2, st: [0, 213, 216, 223, 1, 1, 157, 162, 174, 1], lit: 2))
        case "s_door":
            a.append(VP(k: 1, cx: 0.5, cy: 0.74, w: 0.8, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.3, cy: 0.5, w: 0.34, h: 0.18, rad: 0.04, dir: 0, st: [0, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.6))
            a.append(VP(k: 0, cx: 0.74, cy: 0.5, w: 0.2, h: 0.18, rad: 0.04, dir: 0, st: [0, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.18, cy: 0.5, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 150, 255, 200, 1, 1, 40, 190, 130, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.18, cy: 0.5, w: 0.03, h: 0.03, rad: 0, dir: 2, st: [0, 180, 185, 196, 1, 1, 143, 148, 161, 1], lit: 2))
        case "s_button":
            a.append(VP(k: 1, cx: 0.5, cy: 0.8, w: 0.5, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.52, w: 0.56, h: 0.56, rad: 0, dir: 2, st: [0, 244, 246, 250, 1, 1, 185, 189, 200, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.42, h: 0.42, rad: 0, dir: 3, st: [0, 255, 255, 255, 1, 1, 208, 212, 222, 1], stroke: 0.5))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.1, h: 0.1, rad: 0, dir: 2, st: [0, 180, 160, 255, 1, 1, 120, 90, 230, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.08, h: 0.08, rad: 0, dir: 2, st: [0, 195, 199, 209, 1, 1, 157, 162, 174, 1], lit: 2))
        case "s_smoke":
            a.append(VP(k: 1, cx: 0.5, cy: 0.78, w: 0.6, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.64, h: 0.64, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 1, 195, 199, 209, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.46, h: 0.46, rad: 0, dir: 3, st: [0, 236, 238, 243, 1, 1, 207, 211, 220, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.62, cy: 0.5, w: 0.045, h: 0.045, rad: 0, dir: 2, st: [0, 91, 95, 107, 1, 1, 46, 48, 56, 1]))
            a.append(VP(k: 1, cx: 0.56, cy: 0.6039, w: 0.045, h: 0.045, rad: 0, dir: 2, st: [0, 91, 95, 107, 1, 1, 46, 48, 56, 1]))
            a.append(VP(k: 1, cx: 0.44, cy: 0.6039, w: 0.045, h: 0.045, rad: 0, dir: 2, st: [0, 91, 95, 107, 1, 1, 46, 48, 56, 1]))
            a.append(VP(k: 1, cx: 0.38, cy: 0.5, w: 0.045, h: 0.045, rad: 0, dir: 2, st: [0, 91, 95, 107, 1, 1, 46, 48, 56, 1]))
            a.append(VP(k: 1, cx: 0.44, cy: 0.3961, w: 0.045, h: 0.045, rad: 0, dir: 2, st: [0, 91, 95, 107, 1, 1, 46, 48, 56, 1]))
            a.append(VP(k: 1, cx: 0.56, cy: 0.3961, w: 0.045, h: 0.045, rad: 0, dir: 2, st: [0, 91, 95, 107, 1, 1, 46, 48, 56, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.06, h: 0.06, rad: 0, dir: 2, st: [0, 91, 95, 107, 1, 1, 46, 48, 56, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.24, w: 0.04, h: 0.04, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.5, 255, 100, 100, 1, 1, 153, 60, 60, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.24, w: 0.036, h: 0.036, rad: 0, dir: 2, st: [0, 213, 216, 223, 1, 1, 157, 162, 174, 1], lit: 2))
        case "s_gas":
            a.append(VP(k: 1, cx: 0.5, cy: 0.78, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.62, h: 0.5, rad: 0.12, dir: 0, st: [0, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.6))
            a.append(VP(k: 0, cx: 0.5, cy: 0.42, w: 0.4, h: 0.025, rad: 0.012, dir: 0, st: [0, 143, 148, 161, 1, 1, 195, 199, 209, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.48, w: 0.4, h: 0.025, rad: 0.012, dir: 0, st: [0, 143, 148, 161, 1, 1, 195, 199, 209, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.54, w: 0.4, h: 0.025, rad: 0.012, dir: 0, st: [0, 143, 148, 161, 1, 1, 195, 199, 209, 1]))
            a.append(VP(k: 1, cx: 0.74, cy: 0.64, w: 0.04, h: 0.04, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.5, 255, 190, 90, 1, 1, 153, 114, 54, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.74, cy: 0.64, w: 0.036, h: 0.036, rad: 0, dir: 2, st: [0, 213, 216, 223, 1, 1, 157, 162, 174, 1], lit: 2))
        case "s_vib":
            a.append(VP(k: 1, cx: 0.5, cy: 0.78, w: 0.5, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.5, h: 0.5, rad: 0.12, dir: 3, st: [0, 255, 255, 255, 1, 1, 195, 199, 209, 1], stroke: 0.6))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.36, h: 0.022, rad: 0.011, dir: 1, st: [0, 120, 90, 230, 0, 0.5, 120, 90, 230, 1, 1, 120, 90, 230, 0], lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.36, h: 0.022, rad: 0.011, dir: 1, st: [0, 157, 162, 174, 0, 0.5, 157, 162, 174, 1, 1, 157, 162, 174, 0], lit: 2))
            a.append(VP(k: 0, cx: 0.5, cy: 0.42, w: 0.24, h: 0.02, rad: 0.01, dir: 1, st: [0, 157, 162, 174, 0, 0.5, 157, 162, 174, 1, 1, 157, 162, 174, 0]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.58, w: 0.24, h: 0.02, rad: 0.01, dir: 1, st: [0, 157, 162, 174, 0, 0.5, 157, 162, 174, 1, 1, 157, 162, 174, 0]))
        case "s_light":
            a.append(VP(k: 1, cx: 0.5, cy: 0.78, w: 0.52, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.58, h: 0.58, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.3, h: 0.3, rad: 0, dir: 2, st: [0, 255, 240, 180, 1, 1, 255, 190, 70, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.3, h: 0.3, rad: 0, dir: 2, st: [0, 228, 231, 238, 1, 1, 180, 185, 196, 1], lit: 2))
        case "s_leak":
            a.append(VP(k: 1, cx: 0.5, cy: 0.8, w: 0.7, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.52, w: 0.6, h: 0.6, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 1, 195, 199, 209, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.36, h: 0.36, rad: 0, dir: 3, st: [0, 236, 238, 243, 1, 1, 207, 211, 220, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.52, w: 0.14, h: 0.2, rad: 0, dir: 0, st: [0, 150, 210, 255, 1, 1, 40, 130, 230, 1]))
            a.append(VP(k: 0, cx: 0.36, cy: 0.86, w: 0.025, h: 0.12, rad: 0.012, dir: 0, st: [0, 180, 185, 196, 1, 1, 110, 114, 126, 1]))
            a.append(VP(k: 0, cx: 0.64, cy: 0.86, w: 0.025, h: 0.12, rad: 0.012, dir: 0, st: [0, 180, 185, 196, 1, 1, 110, 114, 126, 1]))
        case "s_climate":
            a.append(VP(k: 1, cx: 0.5, cy: 0.82, w: 0.58, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.54, h: 0.54, rad: 0.12, dir: 3, st: [0, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.6))
            a.append(VP(k: 0, cx: 0.5, cy: 0.46, w: 0.38, h: 0.26, rad: 0.05, dir: 0, st: [0, 46, 48, 56, 1, 1, 15, 16, 19, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.46, w: 0.28, h: 0.06, rad: 0.02, dir: 1, st: [0, 120, 240, 190, 0, 0.5, 120, 240, 190, 1, 1, 120, 240, 190, 0], lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.46, w: 0.28, h: 0.06, rad: 0.02, dir: 1, st: [0, 110, 114, 126, 0, 0.5, 110, 114, 126, 1, 1, 110, 114, 126, 0], lit: 2))
        case "s_generic":
            a.append(VP(k: 1, cx: 0.5, cy: 0.82, w: 0.5, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.54, h: 0.54, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 1, 201, 205, 214, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.44, h: 0.44, rad: 0, dir: 3, st: [0, 244, 246, 250, 1, 1, 217, 220, 227, 1], stroke: 0.4))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.08, h: 0.08, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.5, 150, 110, 255, 1, 1, 90, 66, 153, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.5, w: 0.072, h: 0.072, rad: 0, dir: 2, st: [0, 213, 216, 223, 1, 1, 157, 162, 174, 1], lit: 2))
        case "camera":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.56, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.8, w: 0.24, h: 0.08, rad: 0.03, dir: 0, st: [0, 195, 199, 209, 1, 1, 143, 148, 161, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.68, w: 0.1, h: 0.12, rad: 0.02, dir: 1, st: [0, 143, 148, 161, 1, 0.28, 201, 204, 212, 1, 0.55, 233, 235, 240, 1, 0.82, 201, 204, 212, 1, 1, 143, 148, 161, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.4, w: 0.6, h: 0.6, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 1, 195, 199, 209, 1], stroke: 0.6))
            a.append(VP(k: 1, cx: 0.5, cy: 0.4, w: 0.46, h: 0.46, rad: 0, dir: 2, st: [0, 46, 48, 56, 1, 1, 10, 11, 14, 1], stroke: 0.3))
            a.append(VP(k: 1, cx: 0.5, cy: 0.4, w: 0.28, h: 0.28, rad: 0, dir: 2, st: [0, 58, 74, 138, 1, 0.6, 20, 26, 58, 1, 1, 5, 6, 12, 1]))
            a.append(VP(k: 1, cx: 0.43, cy: 0.33, w: 0.08, h: 0.06, rad: 0, dir: 0, st: [0, 255, 255, 255, 0.7, 1, 255, 255, 255, 0]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.66, w: 0.032, h: 0.032, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.5, 255, 90, 90, 1, 1, 153, 54, 54, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.66, w: 0.0288, h: 0.0288, rad: 0, dir: 2, st: [0, 213, 216, 223, 1, 1, 157, 162, 174, 1], lit: 2))
        case "m_elec":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.58, h: 0.76, rad: 0.07, dir: 1, st: [0, 168, 173, 185, 1, 0.28, 233, 236, 242, 1, 0.55, 255, 255, 255, 1, 0.82, 233, 236, 242, 1, 1, 168, 173, 185, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.4, h: 0.18, rad: 0.04, dir: 0, st: [0, 32, 36, 44, 1, 1, 10, 12, 16, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.32, h: 0.07, rad: 0.02, dir: 1, st: [0, 255, 200, 70, 0, 0.5, 255, 200, 70, 1, 1, 255, 200, 70, 0], lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.32, h: 0.07, rad: 0.02, dir: 1, st: [0, 110, 114, 126, 0, 0.5, 110, 114, 126, 1, 1, 110, 114, 126, 0], lit: 2))
            a.append(VP(k: 0, cx: 0.5, cy: 0.62, w: 0.34, h: 0.2, rad: 0.04, dir: 0, st: [0, 201, 205, 214, 1, 1, 143, 148, 161, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.62, w: 0.22, h: 0.025, rad: 0.012, dir: 0, st: [0, 70, 74, 86, 1, 1, 40, 42, 50, 1]))
        case "m_gas":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.58, h: 0.76, rad: 0.07, dir: 1, st: [0, 168, 173, 185, 1, 0.28, 233, 236, 242, 1, 0.55, 255, 255, 255, 1, 0.82, 233, 236, 242, 1, 1, 168, 173, 185, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.4, h: 0.18, rad: 0.04, dir: 0, st: [0, 32, 36, 44, 1, 1, 10, 12, 16, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.32, h: 0.07, rad: 0.02, dir: 1, st: [0, 255, 140, 70, 0, 0.5, 255, 140, 70, 1, 1, 255, 140, 70, 0], lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.32, h: 0.07, rad: 0.02, dir: 1, st: [0, 110, 114, 126, 0, 0.5, 110, 114, 126, 1, 1, 110, 114, 126, 0], lit: 2))
            a.append(VP(k: 1, cx: 0.5, cy: 0.62, w: 0.3, h: 0.3, rad: 0, dir: 2, st: [0, 217, 220, 227, 1, 1, 157, 162, 174, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.62, w: 0.04, h: 0.2, rad: 0.02, dir: 0, st: [0, 255, 140, 70, 1, 1, 220, 90, 40, 1]))
        case "m_water":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.58, h: 0.76, rad: 0.07, dir: 1, st: [0, 168, 173, 185, 1, 0.28, 233, 236, 242, 1, 0.55, 255, 255, 255, 1, 0.82, 233, 236, 242, 1, 1, 168, 173, 185, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.4, h: 0.18, rad: 0.04, dir: 0, st: [0, 32, 36, 44, 1, 1, 10, 12, 16, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.32, h: 0.07, rad: 0.02, dir: 1, st: [0, 90, 170, 255, 0, 0.5, 90, 170, 255, 1, 1, 90, 170, 255, 0], lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.32, h: 0.07, rad: 0.02, dir: 1, st: [0, 110, 114, 126, 0, 0.5, 110, 114, 126, 1, 1, 110, 114, 126, 0], lit: 2))
            a.append(VP(k: 1, cx: 0.5, cy: 0.62, w: 0.3, h: 0.3, rad: 0, dir: 2, st: [0, 90, 127, 176, 1, 1, 43, 74, 120, 1], stroke: 0.5))
            a.append(VP(k: 1, cx: 0.5, cy: 0.62, w: 0.22, h: 0.22, rad: 0, dir: 2, st: [0, 243, 245, 249, 1, 1, 201, 205, 214, 1]))
        case "m_heat":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.58, h: 0.76, rad: 0.07, dir: 1, st: [0, 168, 173, 185, 1, 0.28, 233, 236, 242, 1, 0.55, 255, 255, 255, 1, 0.82, 233, 236, 242, 1, 1, 168, 173, 185, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.4, h: 0.18, rad: 0.04, dir: 0, st: [0, 32, 36, 44, 1, 1, 10, 12, 16, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.32, h: 0.07, rad: 0.02, dir: 1, st: [0, 255, 120, 90, 0, 0.5, 255, 120, 90, 1, 1, 255, 120, 90, 0], lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.32, h: 0.07, rad: 0.02, dir: 1, st: [0, 110, 114, 126, 0, 0.5, 110, 114, 126, 1, 1, 110, 114, 126, 0], lit: 2))
            a.append(VP(k: 0, cx: 0.5, cy: 0.64, w: 0.34, h: 0.18, rad: 0.04, dir: 0, st: [0, 217, 220, 227, 1, 1, 157, 162, 174, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.64, w: 0.06, h: 0.06, rad: 0, dir: 2, st: [0, 255, 170, 150, 1, 1, 230, 80, 60, 1]))
        case "m_generic":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.5, w: 0.58, h: 0.76, rad: 0.07, dir: 1, st: [0, 168, 173, 185, 1, 0.28, 233, 236, 242, 1, 0.55, 255, 255, 255, 1, 0.82, 233, 236, 242, 1, 1, 168, 173, 185, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.4, h: 0.18, rad: 0.04, dir: 0, st: [0, 32, 36, 44, 1, 1, 10, 12, 16, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.32, h: 0.07, rad: 0.02, dir: 1, st: [0, 150, 110, 255, 0, 0.5, 150, 110, 255, 1, 1, 150, 110, 255, 0], lit: 1))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.32, h: 0.07, rad: 0.02, dir: 1, st: [0, 110, 114, 126, 0, 0.5, 110, 114, 126, 1, 1, 110, 114, 126, 0], lit: 2))
            a.append(VP(k: 0, cx: 0.5, cy: 0.62, w: 0.34, h: 0.2, rad: 0.04, dir: 0, st: [0, 201, 205, 214, 1, 1, 143, 148, 161, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.62, w: 0.22, h: 0.025, rad: 0.012, dir: 0, st: [0, 70, 74, 86, 1, 1, 40, 42, 50, 1]))
        case "pet_feeder":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.34, w: 0.38, h: 0.46, rad: 0.12, dir: 1, st: [0, 201, 206, 217, 1, 0.4, 243, 245, 249, 1, 1, 195, 199, 209, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.12, w: 0.3, h: 0.06, rad: 0.03, dir: 0, st: [0, 157, 162, 174, 1, 1, 110, 114, 126, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.64, w: 0.6, h: 0.18, rad: 0.07, dir: 0, st: [0, 243, 245, 249, 1, 1, 195, 199, 209, 1], stroke: 0.5))
            a.append(VP(k: 1, cx: 0.5, cy: 0.58, w: 0.5, h: 0.12, rad: 0, dir: 0, st: [0, 185, 189, 200, 1, 1, 228, 230, 236, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.585, w: 0.42, h: 0.07, rad: 0, dir: 0, st: [0, 205, 150, 100, 1, 1, 170, 110, 70, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.8, w: 0.5, h: 0.05, rad: 0.025, dir: 0, st: [0, 157, 162, 174, 1, 1, 110, 114, 126, 1]))
        case "pet_fountain":
            a.append(VP(k: 1, cx: 0.5, cy: 0.88, w: 0.74, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.68, w: 0.74, h: 0.28, rad: 0.12, dir: 0, st: [0, 243, 245, 249, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 1, cx: 0.5, cy: 0.58, w: 0.64, h: 0.14, rad: 0, dir: 0, st: [0, 157, 162, 174, 1, 1, 217, 220, 227, 1]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.59, w: 0.56, h: 0.1, rad: 0, dir: 0, st: [0, 150, 210, 255, 1, 1, 90, 170, 245, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.59, w: 0.56, h: 0.1, rad: 0, dir: 0, st: [0, 190, 200, 215, 1, 1, 160, 170, 188, 1], lit: 2))
            a.append(VP(k: 0, cx: 0.5, cy: 0.38, w: 0.16, h: 0.4, rad: 0.08, dir: 1, st: [0, 185, 189, 200, 1, 0.28, 243, 245, 249, 1, 0.55, 255, 255, 255, 1, 0.82, 243, 245, 249, 1, 1, 185, 189, 200, 1], stroke: 0.5))
            a.append(VP(k: 0, cx: 0.5, cy: 0.22, w: 0.3, h: 0.07, rad: 0.035, dir: 0, st: [0, 255, 255, 255, 1, 1, 195, 199, 209, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.4, w: 0.04, h: 0.2, rad: 0.02, dir: 0, st: [0, 150, 210, 255, 0.7, 1, 150, 210, 255, 0], lit: 1))
        case "hub":
            a.append(VP(k: 1, cx: 0.5, cy: 0.84, w: 0.62, h: 0.07, rad: 0, dir: 2, st: [0, 0, 0, 0, 0.34, 1, 0, 0, 0, 0], blur: 0.015))
            a.append(VP(k: 0, cx: 0.5, cy: 0.3, w: 0.04, h: 0.24, rad: 0.02, dir: 1, st: [0, 125, 130, 142, 1, 0.28, 201, 204, 212, 1, 0.55, 236, 238, 242, 1, 0.82, 201, 204, 212, 1, 1, 125, 130, 142, 1]))
            a.append(VP(k: 0, cx: 0.5, cy: 0.6, w: 0.62, h: 0.4, rad: 0.14, dir: 0, st: [0, 255, 255, 255, 1, 1, 195, 199, 209, 1], stroke: 0.6))
            a.append(VP(k: 0, cx: 0.5, cy: 0.54, w: 0.56, h: 0.08, rad: 0.04, dir: 0, st: [0, 255, 255, 255, 0.6, 1, 255, 255, 255, 0]))
            a.append(VP(k: 1, cx: 0.5, cy: 0.64, w: 0.06, h: 0.06, rad: 0, dir: 2, st: [0, 255, 255, 255, 1, 0.5, 150, 110, 255, 1, 1, 90, 66, 153, 1], lit: 1))
            a.append(VP(k: 1, cx: 0.5, cy: 0.64, w: 0.054, h: 0.054, rad: 0, dir: 2, st: [0, 213, 216, 223, 1, 1, 157, 162, 174, 1], lit: 2))
        default: break
        }
        return a
    }

    static var cache: [String: [VP]] = [:]
    static func cached(_ key: String) -> [VP] {
        if let c = cache[key] { return c }
        let l = layers(key)
        cache[key] = l
        return l
    }

    static func supports(_ key: String) -> Bool { return !cached(key).isEmpty }
}

struct VectorIcon: View {
    let key: String
    let size: CGFloat
    let lit: Bool
    let off: Bool

    var body: some View {
        let ls = VP.cached(key)
        ZStack {
            ForEach(Array(ls.enumerated()), id: \.offset) { _, p in
                if p.lit == 0 || (p.lit == 1 && lit) || (p.lit == 2 && !lit) {
                    layer(p)
                }
            }
        }
        .frame(width: size, height: size)
        .shadow(color: Color.black.opacity(0.16), radius: size * 0.012, x: 0, y: size * 0.01)
        .saturation(off ? 0.2 : 1)
        .opacity(off ? 0.85 : 1)
    }

    @ViewBuilder
    func layer(_ p: VP) -> some View {
        let wpx = p.w * size, hpx = p.h * size
        Group {
            if p.k == 0 {
                paint(RoundedRectangle(cornerRadius: p.rad * size, style: .continuous), p)
            } else {
                paint(Ellipse(), p)
            }
        }
        .frame(width: wpx, height: hpx)
        .rotationEffect(.degrees(Double(p.rot)))
        .blur(radius: p.blur * size)
        .offset(x: (p.cx - 0.5) * size, y: (p.cy - 0.5) * size)
    }

    @ViewBuilder
    func paint<S: Shape>(_ s: S, _ p: VP) -> some View {
        if p.ring.count == 3 {
            s.stroke(Color(red: p.ring[0] / 255, green: p.ring[1] / 255, blue: p.ring[2] / 255), lineWidth: size * p.rw)
        } else if p.dir == 2 {
            Circle().fill(RadialGradient(gradient: Gradient(stops: p.stops), center: UnitPoint(x: 0.5, y: 0.4), startRadius: 0, endRadius: p.w * size * 0.6))
                .frame(width: p.w * size, height: p.w * size)
                .scaleEffect(x: 1, y: p.h / p.w)
                .frame(width: p.w * size, height: p.h * size)
                .overlay(strokeLine(s, p))
        } else {
            s.fill(LinearGradient(gradient: Gradient(stops: p.stops), startPoint: VectorIcon.start(p.dir), endPoint: VectorIcon.end(p.dir)))
                .overlay(strokeLine(s, p))
        }
    }

    @ViewBuilder
    func strokeLine<S: Shape>(_ s: S, _ p: VP) -> some View {
        if p.stroke > 0 { s.stroke(Color.white.opacity(Double(p.stroke)), lineWidth: 0.8) }
    }

    static func start(_ d: Int) -> UnitPoint { return d == 1 ? .leading : (d == 3 ? .topLeading : .top) }
    static func end(_ d: Int) -> UnitPoint { return d == 1 ? .trailing : (d == 3 ? .bottomTrailing : .bottom) }
}

/// воздушная подсветка плитки цветом устройства
struct SoftLight: View {
    let color: Color
    var radius: CGFloat = 20

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: radius, style: .continuous)
                .fill(LinearGradient(colors: [color.opacity(0.58), color.opacity(0.30)], startPoint: .topLeading, endPoint: .bottomTrailing))
            RoundedRectangle(cornerRadius: radius, style: .continuous)
                .fill(RadialGradient(colors: [color.opacity(0.95), color.opacity(0.62), color.opacity(0)],
                                     center: UnitPoint(x: 0.2, y: 0.22), startRadius: 0, endRadius: 190))
        }
    }
}

/// кольцо «идёт процесс»: прогресс, если он известен, иначе бегущая дуга
struct BusyRing: View {
    let progress: Double?

    var body: some View {
        TimelineView(.animation) { ctx in
            let t = ctx.date.timeIntervalSinceReferenceDate
            ZStack {
                RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(heatOrange.opacity(0.25), lineWidth: 3)
                if let p = progress {
                    RoundedRectangle(cornerRadius: 18, style: .continuous).trim(from: 0, to: p)
                        .stroke(heatOrange, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                } else {
                    let a = (t.truncatingRemainder(dividingBy: 1.4)) / 1.4
                    RoundedRectangle(cornerRadius: 18, style: .continuous).trim(from: a, to: Swift.min(1, a + 0.25))
                        .stroke(heatOrange, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                }
            }
        }
    }
}

struct FlameBadge: View {
    var body: some View {
        TimelineView(.animation) { ctx in
            let t = ctx.date.timeIntervalSinceReferenceDate
            ZStack {
                Circle().fill(heatOrange).frame(width: 22, height: 22)
                Image(systemName: "flame.fill").font(.system(size: 11, weight: .bold)).foregroundColor(.white)
                    .scaleEffect(0.9 + 0.12 * sin(t * 6))
            }
        }
    }
}

struct PowerButton: View {
    let on: Bool
    let size: CGFloat
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle().fill(on ? purple : pageBG).frame(width: size, height: size)
                    .overlay(Circle().stroke(on ? Color.clear : Color.primary.opacity(0.28), lineWidth: 1.3))
                    .shadow(color: on ? purple.opacity(0.4) : Color.black.opacity(0.12), radius: on ? 4 : 3, x: 0, y: 2)
                Image(systemName: "power").font(.system(size: size * 0.44, weight: .bold))
                    .foregroundColor(on ? Color.white : Color.primary.opacity(0.75))
            }
            .frame(width: size, height: size)
            .contentShape(Circle())
        }.buttonStyle(.plain).focusable(false)
    }
}

struct BigPower: View {
    let on: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle().fill(on ? purple : softBtn).frame(width: 64, height: 64)
                    .shadow(color: on ? purple.opacity(0.45) : Color.clear, radius: 10, x: 0, y: 4)
                Image(systemName: "power").font(.system(size: 26, weight: .semibold))
                    .foregroundColor(on ? Color.white : Color.secondary)
            }
            .frame(width: 70, height: 70)
            .contentShape(Circle())
        }.buttonStyle(.plain).focusable(false)
    }
}

// MARK: - Плитка устройства

// MARK: - Состояние на плитке

func colorOfRGB(_ v: Int) -> Color {
    return Color(red: Double((v >> 16) & 255) / 255, green: Double((v >> 8) & 255) / 255, blue: Double(v & 255) / 255)
}

func kelvinColor(_ k: Double) -> Color {
    let f = Swift.max(0, Swift.min(1, (k - 2700) / 3800))
    return Color(red: 1.0 - 0.28 * f, green: 0.66 + 0.22 * f, blue: 0.3 + 0.7 * f)
}

let lampYellow = Color(red: 1.0, green: 0.76, blue: 0.2)
let offRed = Color(red: 1, green: 0.42, blue: 0.35)

/// цвет, которым сейчас светит лампа
func lightColor(_ d: Dev) -> Color {
    if let c = d.color {
        if c.current == "rgb" { return colorOfRGB(c.rgb) }
        if c.current == "temperature_k" { return kelvinColor(c.tk) }
        if c.current == "scene" { return sceneColors(c.scene)[0] }
    }
    return lampYellow
}

func modeColor(_ v: String) -> Color {
    switch v {
    case "cool": return Color(red: 0.2, green: 0.6, blue: 1)
    case "heat": return Color(red: 1, green: 0.5, blue: 0.2)
    case "dry": return Color(red: 0.1, green: 0.75, blue: 0.75)
    case "fan_only": return Color(red: 0.3, green: 0.75, blue: 0.45)
    case "eco": return Color(red: 0.35, green: 0.75, blue: 0.3)
    default: return purple
    }
}

/// главный цвет включённого устройства (для подсветки плитки)
func accentOf(_ d: Dev) -> Color? {
    guard d.online else { return nil }
    if d.busy { return heatOrange }
    guard d.on == true else { return nil }
    if d.cat == "light" { return lightColor(d) }
    if let m = d.modes.first(where: { $0.instance == "thermostat" }), !m.value.isEmpty { return modeColor(m.value) }
    if d.cat == "climate" { return Color(red: 0.15, green: 0.7, blue: 0.85) }
    if d.isKettle { return heatOrange }
    return purple
}

struct Bit {
    var sym: String? = nil
    var dot: Color? = nil
    var text: String
    var color: Color? = nil
}

/// устройства, которые недавно не выполнили команду (сбой у производителя)
var noAnswer: [String: Date] = [:]

func tileBits(_ d: Dev) -> [Bit] {
    if !d.online { return [Bit(sym: "wifi.slash", text: "Не в сети", color: offRed)] }
    if let t = noAnswer[d.id], Date().timeIntervalSince(t) < 600 {
        return [Bit(sym: "exclamationmark.triangle.fill", text: "Не отвечает", color: Color(red: 1, green: 0.6, blue: 0.1))]
    }
    if d.busy {
        if d.isKettle, d.tempFresh, let c = d.curTemp, let t = d.target {
            return [Bit(sym: "flame.fill", text: Dev.num(c) + "° → " + Dev.num(t.value) + "°", color: heatOrange)]
        }
        return [Bit(sym: d.isKettle ? "flame.fill" : "sparkles", text: d.isKettle ? "Греется…" : "Работает", color: heatOrange)]
    }
    var out: [Bit] = []
    if d.isStation {
        if let s = d.stationLight {
            return [Bit(dot: sceneColors(s)[0], text: "Подсветка: " + (s == "night" ? "Ночник" : sceneTitle(s)))]
        }
        return [Bit(sym: "hifispeaker.fill", text: "Умная колонка")]
    }
    if d.on == true {
        if d.cat == "light" {
            var s = ""
            if let b = d.bright { s = String(Int(b.value.rounded())) + "%" }
            if let c = d.color {
                if c.current == "scene" && !c.scene.isEmpty { s += (s.isEmpty ? "" : " · ") + sceneTitle(c.scene) }
                else if c.current == "temperature_k" { s += (s.isEmpty ? "" : " · ") + String(Int(c.tk.rounded())) + "K" }
            }
            out.append(Bit(dot: lightColor(d), text: s.isEmpty ? "Горит" : s))
        } else if d.isKettle {
            if let c = d.curTemp, d.tempFresh { out.append(Bit(sym: "checkmark.circle.fill", text: "Готово · " + Dev.num(c) + "°", color: Color(red: 0.25, green: 0.7, blue: 0.4))) }
            else { out.append(Bit(sym: "power", text: "Включён", color: purple)) }
        } else {
            if let m = d.modes.first(where: { $0.instance == "thermostat" }), !m.value.isEmpty {
                out.append(Bit(sym: modeValueSymbol(m.value), text: modeValueTitle(m.value), color: modeColor(m.value)))
            } else if let m = d.modes.first, !m.value.isEmpty {
                out.append(Bit(sym: modeValueSymbol(m.value), text: modeValueTitle(m.value), color: purple))
            }
            if let t = d.target { out.append(Bit(text: Dev.num(t.value) + "°")) }
            if let h = d.ranges.first(where: { $0.instance == "humidity" }) { out.append(Bit(sym: "drop.fill", text: String(Int(h.value.rounded())) + "%")) }
            if let v = d.ranges.first(where: { $0.instance == "volume" }), out.isEmpty { out.append(Bit(sym: "speaker.wave.2.fill", text: String(Int(v.value.rounded())))) }
            if d.toggles.contains(where: { $0.instance == "mute" && $0.value }) { out.append(Bit(sym: "speaker.slash.fill", text: "")) }
            if out.isEmpty { out.append(Bit(sym: "power", text: d.isProcess ? "Работает" : "Включено", color: purple)) }
        }
    } else if d.on == false {
        out.append(Bit(text: "Выключено"))
        if d.isKettle, let c = d.curTemp, (d.tempAge ?? 0) < 1800 {
            out.append(Bit(sym: "drop.fill", text: Dev.num(c) + "°" + (d.tempFresh ? "" : " · " + ageText(d.tempAge ?? 1e9))))
        }
    }
    if d.cat != "light" && !d.isKettle {
        for p in d.props {
            switch p.instance {
            case "temperature": out.append(Bit(sym: "thermometer.medium", text: Dev.num(p.value) + "°"))
            case "humidity": out.append(Bit(sym: "humidity.fill", text: String(Int(p.value.rounded())) + "%"))
            case "power": if d.on == true { out.append(Bit(sym: "bolt.fill", text: String(Int(p.value.rounded())) + " Вт")) }
            case "battery_level": if p.value < 25 { out.append(Bit(sym: "battery.25", text: String(Int(p.value.rounded())) + "%", color: offRed)) }
            case "co2_level": out.append(Bit(text: "CO₂ " + String(Int(p.value.rounded()))))
            default: break
            }
        }
    }
    return Array(out.prefix(3))
}

/// тонкий ползунок яркости на плитке
struct TileSlider: View {
    let d: Dev
    let r: RangeCap
    @ObservedObject var m: HomeModel
    let color: Color
    let enabled: Bool

    var body: some View {
        let key = d.id + "." + r.instance
        let cur = m.draft[key] ?? r.value
        let f = CGFloat(Swift.max(0, Swift.min(1, (cur - r.min) / Swift.max(1, r.max - r.min))))
        GeometryReader { g in
            let w = g.size.width
            ZStack(alignment: .leading) {
                Capsule().fill(Color.primary.opacity(0.09)).frame(height: 6)
                Capsule().fill(color).frame(width: Swift.max(6, w * f), height: 6)
                    .shadow(color: enabled ? color.opacity(0.5) : Color.clear, radius: 3)
                Circle().fill(Color.white).frame(width: 16, height: 16)
                    .shadow(color: Color.black.opacity(0.25), radius: 2, x: 0, y: 1)
                    .overlay(Circle().stroke(Color.black.opacity(0.06), lineWidth: 0.5))
                    .offset(x: Swift.max(0, Swift.min(w - 16, w * f - 8)))
                    .opacity(enabled ? 1 : 0.0)
            }
            .frame(width: w, height: 18)
            .contentShape(Rectangle())
            .highPriorityGesture(DragGesture(minimumDistance: 0)
                .onChanged { v in
                    guard enabled else { return }
                    let p = Double(Swift.max(0, Swift.min(1, v.location.x / Swift.max(1, w))))
                    m.draft[key] = Swift.max(1, r.min + p * (r.max - r.min))
                }
                .onEnded { _ in
                    guard enabled, let v = m.draft[key] else { return }
                    m.setRange(d.id, r.instance, v.rounded())
                    m.draft[key] = nil
                })
        }
        .frame(height: 18)
        .help(enabled ? "Яркость" : "Включите, чтобы менять яркость")
    }
}

/// состояние на плитке: главное — заметной цветной «пилюлей», остальное — мелко рядом
struct BitsRow: View {
    let bits: [Bit]

    var body: some View {
        HStack(spacing: 6) {
            ForEach(bits.indices, id: \.self) { i in
                let b = bits[i]
                let tint: Color? = b.dot ?? b.color
                if i == 0, let t = tint {
                    HStack(spacing: 4) {
                        if b.dot != nil {
                            Circle().fill(t).frame(width: 8, height: 8)
                                .shadow(color: t.opacity(0.8), radius: 3)
                        } else if let s = b.sym {
                            Image(systemName: s).font(.system(size: 9, weight: .bold)).foregroundColor(t)
                        }
                        if !b.text.isEmpty {
                            Text(b.text).lineLimit(1).foregroundColor(Color.primary.opacity(0.85))
                        }
                    }
                    .padding(.horizontal, 7).padding(.vertical, 3)
                    .background(Capsule().fill(Color(NSColor.windowBackgroundColor).opacity(0.72)))
                    .overlay(Capsule().stroke(t.opacity(0.7), lineWidth: 1))
                } else {
                    HStack(spacing: 3) {
                        if let c = b.dot { Circle().fill(c).frame(width: 7, height: 7) }
                        if let s = b.sym { Image(systemName: s).font(.system(size: 9, weight: .bold)) }
                        if !b.text.isEmpty { Text(b.text).lineLimit(1) }
                    }
                    .foregroundColor(b.color ?? Color.secondary)
                }
            }
        }
        .font(.system(size: 11, weight: .semibold))
        .lineLimit(1)
        .frame(height: 20, alignment: .leading)
    }
}

struct Tile: View {
    let d: Dev
    @ObservedObject var m: HomeModel
    var ctx: String = "r"

    /// устройство с учётом того, что сейчас тянут ползунок
    var dv: Dev {
        var x = d
        if let v = m.draft[d.id + ".brightness"] {
            for i in x.ranges.indices where x.ranges[i].instance == "brightness" { x.ranges[i].value = v.rounded() }
        }
        return x
    }

    var body: some View {
        let key = ctx + "|" + d.id
        let lit = (d.on ?? false) && d.online
        let hot = m.hover == key || m.quickID == key
        let acc = accentOf(d)
        ZStack(alignment: .topLeading) {
            RoundedRectangle(cornerRadius: 20, style: .continuous).fill(hot ? tileHover : tileBG)
            if let a = acc {
                // мягкий рассеянный свет от устройства, без резких заливок
                SoftLight(color: a)
            }
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .stroke(m.quickID == key ? purple.opacity(0.7) : (acc != nil ? acc!.opacity(0.7) : Color.primary.opacity(0.09)), lineWidth: 1.2)
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .top, spacing: 0) {
                    ZStack(alignment: .bottomTrailing) {
                        DevImage(d: d, size: 62)
                        if d.busy {
                            BusyRing(progress: d.progress).frame(width: 66, height: 66)
                            FlameBadge().offset(x: 6, y: 6)
                        }
                    }
                    .frame(width: 66, height: 66)
                    Spacer(minLength: 2)
                    if !d.online {
                        Image(systemName: "wifi.slash").font(.system(size: 14, weight: .semibold))
                            .foregroundColor(offRed).frame(width: 34, height: 34)
                    } else if d.on != nil {
                        PowerButton(on: lit, size: 34, action: { m.setOn(d.id, !(d.on ?? false)) })
                    }
                }
                Spacer(minLength: 0)
                HStack(spacing: 4) {
                    if ctx != "fav" && m.isFav(d.id) {
                        Image(systemName: "star.fill").font(.system(size: 9)).foregroundColor(lampYellow)
                    }
                    Text(d.name).font(.system(size: 13, weight: .semibold)).lineLimit(1).truncationMode(.tail)
                        .foregroundColor(d.online ? Color.primary : Color.secondary)
                }
                BitsRow(bits: tileBits(dv)).padding(.top, 4)
                if let br = d.bright, d.online {
                    // яркость — прямо с плитки
                    TileSlider(d: d, r: br, m: m, color: lit ? lightColor(d) : Color.secondary.opacity(0.5), enabled: lit)
                        .padding(.top, 8)
                }
            }
            .padding(.horizontal, 12).padding(.top, 10).padding(.bottom, 11)
            if d.busy, let p = d.progress {
                VStack {
                    Spacer()
                    GeometryReader { g in
                        ZStack(alignment: .leading) {
                            Capsule().fill(heatOrange.opacity(0.18))
                            Capsule().fill(heatOrange).frame(width: g.size.width * CGFloat(p))
                        }
                    }
                    .frame(height: 4)
                    .padding(.horizontal, 14).padding(.bottom, 5)
                }
            }
        }
        .frame(height: 152)
        .contentShape(Rectangle())
        .onHover { h in
            if h {
                m.hover = key
                m.tileEnter(key, d.id)
            } else {
                if m.hover == key { m.hover = nil }
                m.tileExit(key)
            }
        }
        .onTapGesture { m.openDetail(d.id) }
        .contextMenu {
            Button(m.isFav(d.id) ? "Убрать из избранного" : "Добавить в избранное") { m.toggleFav(d.id) }
            if m.isFav(d.id) && ctx == "fav" {
                Button("Сдвинуть левее") { m.moveFav(d.id, -1) }
                Button("Сдвинуть правее") { m.moveFav(d.id, 1) }
            }
            Divider()
            if d.on != nil && d.online {
                Button(d.on == true ? "Выключить" : "Включить") { m.setOn(d.id, !(d.on ?? false)) }
            }
            Button("Открыть настройки") { m.openDetail(d.id) }
        }
        .popover(isPresented: Binding<Bool>(get: { m.quickID == key },
                                            set: { v in if !v && m.quickID == key { m.quickID = nil } }),
                 arrowEdge: .trailing) {
            QuickPanel(id: d.id, m: m)
        }
    }
}

struct ChipView: View {
    let symbol: String
    let tint: Color
    let title: String
    let sub: String
    let selected: Bool

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: symbol).font(.system(size: 16, weight: .semibold)).foregroundColor(tint).frame(width: 20)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Text(sub).font(.system(size: 11)).foregroundColor(.secondary).lineLimit(1)
            }
        }
        .frame(minWidth: 104, alignment: .leading)
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(selected ? tint.opacity(0.2) : tileBG))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(selected ? tint : Color.clear, lineWidth: 1.5))
    }
}

struct ChipsRow: View {
    @ObservedObject var m: HomeModel

    var body: some View {
        let devs = m.allDevices
        let off = devs.filter { !$0.online }.count
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                if off > 0 {
                    Button(action: { m.toggleFilter("offline") }) {
                        ChipView(symbol: "wifi.slash", tint: Color(red: 1, green: 0.42, blue: 0.35), title: "Не в сети", sub: "\(off) устр", selected: m.filter == "offline")
                    }.buttonStyle(.plain).focusable(false)
                }
                ForEach(allCats, id: \.key) { c in
                    let list = devs.filter { $0.cat == c.key }
                    if !list.isEmpty {
                        let lit = list.filter { ($0.on ?? false) && $0.online }.count
                        let hasSwitch = list.contains { $0.on != nil }
                        Button(action: { m.toggleFilter(c.key) }) {
                            ChipView(symbol: c.symbol, tint: c.tint, title: c.title,
                                     sub: hasSwitch ? "\(list.count) • \(lit) вкл" : "\(list.count) устр", selected: m.filter == c.key)
                        }.buttonStyle(.plain).focusable(false)
                    }
                }
            }
            .padding(.horizontal, 16)
        }
    }
}

struct BusyBanner: View {
    let d: Dev
    @ObservedObject var m: HomeModel

    var body: some View {
        HStack(spacing: 12) {
            ZStack(alignment: .bottomTrailing) {
                DevImage(d: d, size: 44)
                FlameBadge().scaleEffect(0.8).offset(x: 5, y: 5)
            }
            .frame(width: 48, height: 48)
            VStack(alignment: .leading, spacing: 5) {
                HStack {
                    Text(d.name).font(.system(size: 13, weight: .bold)).lineLimit(1)
                    Spacer()
                    Text(d.statusLine ?? "Работает").font(.system(size: 12, weight: .semibold)).foregroundColor(heatOrange).lineLimit(1)
                }
                TimelineView(.animation) { ctx in
                    let t = ctx.date.timeIntervalSinceReferenceDate
                    GeometryReader { g in
                        ZStack(alignment: .leading) {
                            Capsule().fill(heatOrange.opacity(0.2))
                            if let p = d.progress {
                                Capsule().fill(LinearGradient(colors: [Color(red: 1, green: 0.75, blue: 0.2), heatOrange], startPoint: .leading, endPoint: .trailing))
                                    .frame(width: g.size.width * CGFloat(p))
                            } else {
                                let a = CGFloat(t.truncatingRemainder(dividingBy: 1.6) / 1.6)
                                Capsule().fill(heatOrange).frame(width: g.size.width * 0.3)
                                    .offset(x: (g.size.width * 1.3) * a - g.size.width * 0.3)
                            }
                        }
                        .clipShape(Capsule())
                    }
                }
                .frame(height: 6)
            }
            PowerButton(on: true, size: 32, action: { m.setOn(d.id, false) })
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 20, style: .continuous).fill(pageBG))
        .background(RoundedRectangle(cornerRadius: 20, style: .continuous).fill(heatOrange.opacity(0.14)).padding(-1))
        .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).stroke(heatOrange.opacity(0.5), lineWidth: 1))
        .shadow(color: Color.black.opacity(0.18), radius: 12, x: 0, y: 4)
        .contentShape(Rectangle())
        .onTapGesture { m.openDetail(d.id) }
    }
}

struct RoomSection: View {
    let room: Room
    @ObservedObject var m: HomeModel
    let cols = [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)]

    var body: some View {
        let anyOn = room.devices.contains { ($0.on ?? false) && $0.online }
        let canSwitch = room.devices.contains { $0.on != nil && $0.online }
        let isNone = room.id.hasPrefix("none") || room.name.lowercased().contains("не подключ")
        let closed = (isNone ? !m.collapsed.contains(room.id) : m.collapsed.contains(room.id)) && m.filter == nil
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Button(action: { m.toggleCollapse(room.id) }) {
                    HStack(spacing: 6) {
                        Text(room.name).font(.system(size: 18, weight: .bold))
                        if closed {
                            Text("\(room.devices.count)").font(.system(size: 12, weight: .bold)).foregroundColor(.secondary)
                                .padding(.horizontal, 7).padding(.vertical, 2)
                                .background(Capsule().fill(softBtn))
                        }
                        Image(systemName: "chevron.right").font(.system(size: 13, weight: .bold)).foregroundColor(.secondary)
                            .rotationEffect(.degrees(closed ? 0 : 90))
                    }
                }.buttonStyle(.plain).focusable(false)
                .contextMenu {
                    Button("В самый верх") { m.moveRoom(room.id, -1000) }
                    Button("В самый низ") { m.moveRoom(room.id, 1000) }
                    Divider()
                    Button(closed ? "Развернуть" : "Свернуть") { m.toggleCollapse(room.id) }
                }
                if m.filter == nil {
                    // ручка: появляется при наведении, потяните — комната переедет
                    Image(systemName: "line.3.horizontal")
                        .font(.system(size: 13, weight: .semibold)).foregroundColor(.secondary)
                        .frame(width: 26, height: 22)
                        .contentShape(Rectangle())
                        .opacity(m.hoverRoom == room.id || m.draggingRoom == room.id ? 1 : 0)
                        .help("Потяните, чтобы переместить комнату")
                        .onDrag {
                            m.draggingRoom = room.id
                            return NSItemProvider(object: room.id as NSString)
                        }
                }
                Spacer()
                if canSwitch {
                    Button(action: { m.setRoom(room, on: !anyOn) }) {
                        Text(anyOn ? "Выключить всё" : "Включить всё").font(.system(size: 12, weight: .semibold)).foregroundColor(purple)
                            .frame(width: 110, alignment: .trailing)
                    }.buttonStyle(.plain).focusable(false)
                }
            }
            if !closed {
                LazyVGrid(columns: cols, spacing: 10) {
                    ForEach(room.devices) { d in
                        Tile(d: d, m: m)
                    }
                }
            }
        }
        .onHover { h in
            if h { m.hoverRoom = room.id } else if m.hoverRoom == room.id { m.hoverRoom = nil }
            if NSEvent.pressedMouseButtons == 0 && m.draggingRoom != nil { m.draggingRoom = nil }
        }
        .opacity(m.draggingRoom == room.id ? 0.55 : 1)
        .onDrop(of: ["public.text", "public.utf8-plain-text"], delegate: RoomDropDelegate(target: room.id, m: m))
    }
}

struct RoomDropDelegate: DropDelegate {
    let target: String
    let m: HomeModel

    func validateDrop(info: DropInfo) -> Bool { return m.draggingRoom != nil }
    func dropEntered(info: DropInfo) {
        if let d = m.draggingRoom { m.moveRoomTo(d, target) }
    }
    func dropUpdated(info: DropInfo) -> DropProposal? { return DropProposal(operation: .move) }
    func performDrop(info: DropInfo) -> Bool {
        m.draggingRoom = nil
        return true
    }
}

struct DevicesPage: View {
    @ObservedObject var m: HomeModel

    var body: some View {
        let rooms = m.visibleRooms
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                ChipsRow(m: m).padding(.horizontal, -16)
                if let f = m.filter, f != "offline" {
                    let c = catFor(f)
                    let all = m.allDevices.filter { $0.cat == f && $0.on != nil && $0.online }
                    if !all.isEmpty {
                        let anyOn = all.contains { $0.on == true }
                        Button(action: { m.setCategory(f, on: !anyOn) }) {
                            Text(anyOn ? "Выключить: " + c.title.lowercased() : "Включить: " + c.title.lowercased())
                                .font(.system(size: 13, weight: .semibold)).foregroundColor(Color.white)
                                .padding(.horizontal, 16).padding(.vertical, 8)
                                .background(Capsule().fill(purple))
                        }.buttonStyle(.plain).focusable(false)
                    }
                }
                if m.filter == nil && !m.favDevices.isEmpty {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 6) {
                            Image(systemName: "star.fill").font(.system(size: 15)).foregroundColor(lampYellow)
                            Text("Избранное").font(.system(size: 19, weight: .bold))
                        }
                        LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 10) {
                            ForEach(m.favDevices) { d in
                                Tile(d: d, m: m, ctx: "fav")
                            }
                        }
                    }
                }
                ForEach(rooms) { r in
                    RoomSection(room: r, m: m)
                }
                if rooms.isEmpty {
                    Text("Здесь пока ничего нет").font(.system(size: 13)).foregroundColor(.secondary)
                        .frame(maxWidth: .infinity).padding(.top, 40)
                }
            }
            .padding(.horizontal, 16).padding(.top, 4).padding(.bottom, 96)
        }
    }
}

struct ScenariosPage: View {
    @ObservedObject var m: HomeModel
    let cols = [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)]

    var body: some View {
        ScrollView {
            if m.scenarios.isEmpty {
                Text("Сценариев пока нет. Создайте их в приложении «Дом с Алисой».")
                    .font(.system(size: 13)).foregroundColor(.secondary).multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity).padding(40)
            } else {
                LazyVGrid(columns: cols, spacing: 10) {
                    ForEach(m.scenarios) { s in
                        let done = m.ranScenario == s.id
                        Button(action: { m.run(s) }) {
                            HStack(spacing: 10) {
                                ZStack {
                                    Circle().fill(done ? purple : purple.opacity(0.15)).frame(width: 36, height: 36)
                                    Image(systemName: done ? "checkmark" : "play.fill").font(.system(size: 13, weight: .bold))
                                        .foregroundColor(done ? Color.white : purple)
                                }
                                Text(s.name).font(.system(size: 14, weight: .semibold)).lineLimit(2).multilineTextAlignment(.leading)
                                Spacer(minLength: 0)
                            }
                            .padding(12)
                            .frame(height: 64)
                            .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(tileBG))
                        }.buttonStyle(.plain).focusable(false)
                    }
                }
                .padding(16)
            }
        }
    }
}

// MARK: - Управление устройством (общие элементы)

struct OptionChip: View {
    let title: String
    let symbol: String?
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                if let s = symbol { Image(systemName: s).font(.system(size: 11, weight: .semibold)) }
                Text(title).font(.system(size: 12, weight: .semibold)).lineLimit(1).minimumScaleFactor(0.8)
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, 8).padding(.vertical, 8)
            .background(Capsule().fill(selected ? purple.opacity(0.14) : Color.primary.opacity(0.045)))
            .overlay(Capsule().stroke(selected ? purple.opacity(0.85) : Color.primary.opacity(0.06), lineWidth: selected ? 1.5 : 1))
            .foregroundColor(selected ? purple : Color.primary)
            .contentShape(Capsule())
        }.buttonStyle(.plain).focusable(false)
    }
}

struct SectionLabel: View {
    let symbol: String
    let title: String
    let value: String?

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: symbol).font(.system(size: 11, weight: .semibold)).foregroundColor(.secondary).frame(width: 14)
            Text(title).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
            Spacer()
            if let v = value { Text(v).font(.system(size: 12, weight: .semibold)) }
        }
    }
}

struct GradientSlider: View {
    let key: String
    let lo: Double
    let hi: Double
    let value: Double
    let colors: [Color]
    @ObservedObject var m: HomeModel
    let commit: (Double) -> Void

    var body: some View {
        let cur = m.draft[key] ?? value
        let frac = hi > lo ? (cur - lo) / (hi - lo) : 0
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(LinearGradient(colors: colors, startPoint: .leading, endPoint: .trailing)).frame(height: 26)
                Circle().fill(Color.white).frame(width: 22, height: 22)
                    .shadow(color: Color.black.opacity(0.3), radius: 2, x: 0, y: 1)
                    .offset(x: 2 + Swift.max(0, Swift.min(1, CGFloat(frac))) * (g.size.width - 26))
            }
            .frame(height: 26)
            .contentShape(Rectangle())
            .gesture(DragGesture(minimumDistance: 0)
                .onChanged { v in
                    let f = Swift.max(0, Swift.min(1, Double((v.location.x - 13) / Swift.max(1, g.size.width - 26))))
                    m.draft[key] = lo + f * (hi - lo)
                }
                .onEnded { _ in
                    if let v = m.draft[key] { commit(v.rounded()) }
                    m.draft[key] = nil
                })
        }
        .frame(height: 26)
    }
}

/// «толстый» ползунок как на iPhone: заливка показывает значение
struct FillSlider: View {
    let key: String
    let lo: Double
    let hi: Double
    let value: Double
    let symbol: String
    @ObservedObject var m: HomeModel
    let commit: (Double) -> Void

    var body: some View {
        let cur = m.draft[key] ?? value
        let frac = hi > lo ? Swift.max(0, Swift.min(1, (cur - lo) / (hi - lo))) : 0
        GeometryReader { g in
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 12, style: .continuous).fill(softBtn)
                RoundedRectangle(cornerRadius: 12, style: .continuous).fill(purple)
                    .frame(width: Swift.max(24, g.size.width * CGFloat(frac)))
                Image(systemName: symbol).font(.system(size: 13, weight: .semibold))
                    .foregroundColor(frac > 0.08 ? Color.white : Color.secondary).padding(.leading, 10)
            }
            .contentShape(Rectangle())
            .gesture(DragGesture(minimumDistance: 0)
                .onChanged { v in
                    let f = Swift.max(0, Swift.min(1, Double(v.location.x / Swift.max(1, g.size.width))))
                    m.draft[key] = lo + f * (hi - lo)
                }
                .onEnded { _ in
                    if let v = m.draft[key] { commit(v.rounded()) }
                    m.draft[key] = nil
                })
        }
        .frame(height: 36)
    }
}

struct RangeControl: View {
    let d: Dev
    let r: RangeCap
    @ObservedObject var m: HomeModel

    var body: some View {
        let key = d.id + "." + r.instance
        let cur = m.draft[key] ?? r.value
        VStack(alignment: .leading, spacing: 10) {
            if r.instance == "temperature" || r.instance == "channel" {
                SectionLabel(symbol: rangeSymbol(r.instance), title: rangeTitle(d, r.instance), value: nil)
                HStack(spacing: 14) {
                    Button(action: { m.setRange(d.id, r.instance, Swift.max(r.min, r.value - r.step)) }) {
                        ZStack { Circle().fill(softBtn).frame(width: 40, height: 40); Image(systemName: "minus").font(.system(size: 16, weight: .bold)) }
                    }.buttonStyle(.plain).focusable(false)
                    Spacer()
                    VStack(spacing: 0) {
                        Text(Dev.num(r.value) + r.unit).font(.system(size: 34, weight: .bold)).monospacedDigit()
                        if r.instance == "temperature", let c = d.curTemp {
                            Text((d.tempFresh ? "сейчас " : "было ") + Dev.num(c) + "°" + ((d.tempAge ?? 1e9) >= 90 ? " · " + ageText(d.tempAge ?? 1e9) : ""))
                                .font(.system(size: 11)).foregroundColor(.secondary)
                        }
                    }
                    Spacer()
                    Button(action: { m.setRange(d.id, r.instance, Swift.min(r.max, r.value + r.step)) }) {
                        ZStack { Circle().fill(softBtn).frame(width: 40, height: 40); Image(systemName: "plus").font(.system(size: 16, weight: .bold)) }
                    }.buttonStyle(.plain).focusable(false)
                }
                if d.isKettle && r.instance == "temperature" {
                    let presets = [40.0, 60.0, 70.0, 80.0, 90.0, 100.0].filter { $0 >= r.min && $0 <= r.max }
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 46), spacing: 6)], spacing: 6) {
                        ForEach(presets, id: \.self) { p in
                            OptionChip(title: Dev.num(p) + "°", symbol: nil, selected: abs(r.value - p) < 0.5, action: { m.setRange(d.id, r.instance, p) })
                        }
                    }
                }
            } else {
                SectionLabel(symbol: rangeSymbol(r.instance), title: rangeTitle(d, r.instance), value: String(Int(cur.rounded())) + r.unit)
                FillSlider(key: key, lo: r.min, hi: r.max, value: r.value, symbol: rangeSymbol(r.instance), m: m,
                           commit: { v in m.setRange(d.id, r.instance, v) })
            }
        }
        .card()
    }
}

struct ColorControl: View {
    let d: Dev
    let c: ColorCap
    @ObservedObject var m: HomeModel
    /// "scenes" — только сцены, "colors" — только цвет и белый свет (сворачивается)
    var part: String = "all"
    let hues: [Double] = [0, 18, 36, 52, 90, 140, 175, 200, 220, 245, 270, 295, 320]
    let whites: [Double] = [2700, 3400, 4000, 5000, 6500]

    func whiteColor(_ k: Double) -> Color {
        let f = Swift.max(0, Swift.min(1, (k - 2700) / 3800))
        return Color(red: 1.0 - 0.25 * f, green: 0.78 + 0.12 * f, blue: 0.5 + 0.5 * f)
    }

    var body: some View {
        let showColors = part != "scenes"
        VStack(alignment: .leading, spacing: 12) {
            if showColors && !c.model.isEmpty {
                SectionLabel(symbol: "paintpalette.fill", title: "Цвет", value: nil)
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 30), spacing: 8)], spacing: 8) {
                    ForEach(hues, id: \.self) { h in
                        let sel = c.current == "rgb" && abs(hueOf(c.rgb) - h) < 9
                        Button(action: { m.setHue(d.id, h, 100) }) {
                            ZStack {
                                Circle().fill(Color(hue: h / 360, saturation: 0.85, brightness: 1.0)).frame(width: 30, height: 30)
                                Circle().stroke(sel ? Color.primary : Color.clear, lineWidth: 2.5).frame(width: 36, height: 36)
                            }
                            .frame(width: 36, height: 36)
                        }.buttonStyle(.plain).focusable(false)
                    }
                }
            }
            if showColors && c.hasTK {
                let cur = m.draft[d.id + ".tk"] ?? c.tk
                SectionLabel(symbol: "sun.max", title: "Белый свет", value: String(Int(cur.rounded())) + " K")
                HStack(spacing: 8) {
                    ForEach(whites.filter { $0 >= c.tkMin - 1 && $0 <= c.tkMax + 1 }, id: \.self) { k in
                        let sel = c.current == "temperature_k" && abs(c.tk - k) < 150
                        Button(action: { m.setTK(d.id, k) }) {
                            ZStack {
                                Circle().fill(whiteColor(k)).frame(width: 30, height: 30)
                                    .overlay(Circle().stroke(Color.black.opacity(0.08), lineWidth: 1))
                                Circle().stroke(sel ? Color.primary : Color.clear, lineWidth: 2.5).frame(width: 36, height: 36)
                            }
                            .frame(width: 36, height: 36)
                        }.buttonStyle(.plain).focusable(false)
                    }
                }
                GradientSlider(key: d.id + ".tk", lo: c.tkMin, hi: c.tkMax, value: c.tk,
                               colors: [Color(red: 1.0, green: 0.68, blue: 0.32), Color(red: 1, green: 0.96, blue: 0.9), Color(red: 0.75, green: 0.87, blue: 1.0)],
                               m: m, commit: { v in m.setTK(d.id, v) })
            }
            if part != "colors" && !c.scenes.isEmpty {
                SectionLabel(symbol: d.isStation ? "light.max" : "sparkles", title: d.isStation ? "Подсветка станции" : "Режимы", value: nil)
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 120), spacing: 6)], spacing: 6) {
                    ForEach(stationOrder(c.scenes, d.isStation), id: \.self) { s in
                        let sel = (c.current == "scene" && c.scene == s) || (d.isStation && s == "inactive" && d.stationLight == nil)
                        Button(action: { m.setScene(d.id, s) }) {
                            ScenePreview(scene: s, title: d.isStation && s == "night" ? "Ночник" : sceneTitle(s), selected: sel)
                        }.buttonStyle(.plain).focusable(false)
                    }
                }
            }
        }
        .card()
    }
}

/// «шарик света» сцены: мягкое свечение реальных цветов; у динамичных — медленно переливается
struct SceneOrb: View {
    let scene: String
    let size: CGFloat

    var body: some View {
        let cols = sceneColors(scene)
        let moves = sceneMoves(scene)
        TimelineView(.animation(minimumInterval: 1.0 / 24, paused: !moves)) { ctx in
            let t = ctx.date.timeIntervalSinceReferenceDate
            let fast = ["party", "garland", "siren", "alarm", "disco", "pulse", "storm", "thunderstorm"].contains(scene)
            let w = moves ? t * (fast ? 2.4 : 0.7) : 0
            ZStack {
                // мягкое свечение вокруг — цветом сцены
                Circle().fill(cols[0]).frame(width: size, height: size).blur(radius: size * 0.3).opacity(0.5)
                ZStack {
                    Circle().fill(cols[cols.count > 1 ? 1 : 0])
                    ForEach(cols.indices, id: \.self) { k in
                        let a = w + Double(k) * 2 * Double.pi / Double(cols.count)
                        Circle().fill(cols[k])
                            .frame(width: size * 0.62, height: size * 0.62)
                            .offset(x: CGFloat(cos(a)) * size * 0.2, y: CGFloat(sin(a)) * size * 0.2)
                            .blur(radius: size * 0.1)
                    }
                    // лёгкий блик сверху
                    Ellipse().fill(Color.white.opacity(0.35)).frame(width: size * 0.36, height: size * 0.2)
                        .offset(x: -size * 0.1, y: -size * 0.2).blur(radius: 2)
                }
                .frame(width: size * 0.8, height: size * 0.8)
                .clipShape(Circle())
                .overlay(Circle().stroke(Color.black.opacity(0.06), lineWidth: 0.5))
            }
            .frame(width: size, height: size)
        }
    }
}

/// карточка сцены: лёгкая, с «шариком света» и подсказкой, как она светит
struct ScenePreview: View {
    let scene: String
    let title: String
    let selected: Bool

    var body: some View {
        let cols = sceneColors(scene)
        HStack(spacing: 10) {
            Circle()
                .fill(LinearGradient(colors: cols.count > 1 ? cols : [cols[0], cols[0]], startPoint: .topLeading, endPoint: .bottomTrailing))
                .frame(width: 26, height: 26)
                .overlay(Circle().stroke(Color.primary.opacity(0.10), lineWidth: 0.5))
            // название не растягивает плитку: лежит поверх пустого места, длинное плавно уходит в белый
            Color.clear.frame(maxWidth: .infinity).frame(height: 20)
                .overlay(
                    Text(title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                        .foregroundColor(.primary),
                    alignment: .leading)
                .clipped()
                .mask(LinearGradient(stops: [.init(color: .black, location: 0), .init(color: .black, location: 0.8), .init(color: .clear, location: 1)],
                                     startPoint: .leading, endPoint: .trailing))
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 11).padding(.vertical, 13)
        .background(ZStack {
            RoundedRectangle(cornerRadius: 13, style: .continuous).fill(pageBG)
            if selected {
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .fill(LinearGradient(colors: (cols.count > 1 ? cols : [cols[0], cols[0]]).map { $0.opacity(0.38) },
                                         startPoint: .leading, endPoint: .trailing))
            }
        })
        .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous)
            .stroke(selected ? purple : Color.primary.opacity(0.16), lineWidth: selected ? 1.8 : 1))
        .contentShape(Rectangle())
    }
}

struct ModeControl: View {
    let d: Dev
    let mc: ModeCap
    @ObservedObject var m: HomeModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel(symbol: "dial.medium.fill", title: modeTitle(mc.instance), value: nil)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 84), spacing: 6)], spacing: 6) {
                ForEach(mc.values, id: \.self) { v in
                    OptionChip(title: modeValueTitle(v), symbol: modeValueSymbol(v), selected: mc.value == v, action: { m.setMode(d.id, mc.instance, v) })
                }
            }
        }
        .card()
    }
}

struct DeviceControls: View {
    let d: Dev
    @ObservedObject var m: HomeModel

    var body: some View {
        VStack(spacing: 10) {
            if d.online {
                // сначала то, что переключают чаще всего: режимы
                if let c = d.color, !c.scenes.isEmpty {
                    ColorControl(d: d, c: c, m: m, part: "scenes")
                }
                ForEach(d.modes, id: \.instance) { mc in
                    ModeControl(d: d, mc: mc, m: m)
                }
                ForEach(d.ranges, id: \.instance) { r in
                    RangeControl(d: d, r: r, m: m)
                }
                // цвет и белый свет нужны реже — внизу
                if let c = d.color, !c.model.isEmpty || c.hasTK {
                    ColorControl(d: d, c: c, m: m, part: "colors")
                }
                if !d.toggles.isEmpty {
                    VStack(spacing: 0) {
                        ForEach(d.toggles, id: \.instance) { t in
                            HStack(spacing: 10) {
                                Image(systemName: toggleSymbol(t.instance)).font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(.secondary).frame(width: 18)
                                Text(toggleTitle(t.instance)).font(.system(size: 13))
                                Spacer()
                                Toggle("", isOn: Binding<Bool>(get: { t.value }, set: { m.setToggle(d.id, t.instance, $0) }))
                                    .toggleStyle(.switch).labelsHidden().controlSize(.small)
                            }
                            .padding(.vertical, 6)
                        }
                    }
                    .card()
                }
            }
            if !d.props.isEmpty {
                VStack(spacing: 0) {
                    ForEach(d.props.indices, id: \.self) { i in
                        HStack {
                            Text(propTitle(d.props[i].instance)).font(.system(size: 13)).foregroundColor(.secondary)
                            Spacer()
                            Text(propValue(d.props[i])).font(.system(size: 14, weight: .semibold)).monospacedDigit()
                        }
                        .padding(.vertical, 8)
                        if i < d.props.count - 1 { Divider() }
                    }
                }
                .card()
            }
            if d.online && !d.others.filter({ $0.isButton }).isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Кнопки").font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)], spacing: 8) {
                        ForEach(d.others.filter { $0.isButton }, id: \.instance) { o in
                            Button(action: { m.pressButton(d.id, o) }) {
                                Text(o.title).font(.system(size: 12.5, weight: .semibold)).lineLimit(1)
                                    .frame(maxWidth: .infinity).padding(.vertical, 9)
                                    .background(Capsule().fill(purple.opacity(0.12)))
                                    .foregroundColor(purple)
                                    .contentShape(Capsule())
                            }.buttonStyle(.plain).focusable(false)
                        }
                    }
                }
                .card()
            }
            if d.online && d.on == nil && d.ranges.isEmpty && d.modes.isEmpty && d.toggles.isEmpty && d.color == nil
                && d.others.filter({ $0.isButton }).isEmpty {
                NoControlsCard(d: d, m: m)
            }
        }
    }
}

/// у устройства нет кнопок: объясняем почему и даём вернуть скрытые
struct NoControlsCard: View {
    let d: Dev
    @ObservedObject var m: HomeModel

    var body: some View {
        let hidden = m.badCaps.filter { $0.hasPrefix(d.id + "|") }.count
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "info.circle.fill").foregroundColor(.secondary)
                Text("Управления нет").font(.system(size: 13, weight: .semibold))
            }
            if hidden > 0 {
                Text("Раньше Яндекс отклонил команды для этого устройства, и виджет спрятал кнопки (\(hidden)). Если устройство снова работает через приложение «Дом с Алисой», верните их.")
                    .font(.system(size: 12)).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                Button(action: { m.restoreCaps(d.id) }) {
                    Text("Вернуть кнопки").font(.system(size: 12.5, weight: .semibold)).foregroundColor(.white)
                        .padding(.horizontal, 14).padding(.vertical, 7)
                        .background(Capsule().fill(purple))
                }.buttonStyle(.plain).focusable(false)
            } else {
                Text("Яндекс не передал для этого устройства команд, которыми можно управлять извне (так бывает у устройств, подключённых через ИК-пульт или навык производителя). В приложении «Дом с Алисой» они могут быть.")
                    .font(.system(size: 12)).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if !d.rawCaps.isEmpty {
                Text("Возможности по данным Яндекса: " + d.rawCaps.joined(separator: ", "))
                    .font(.system(size: 10.5)).foregroundColor(Color.secondary.opacity(0.8)).fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Яндекс не передал ни одной возможности.").font(.system(size: 10.5)).foregroundColor(Color.secondary.opacity(0.8))
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }
}

func panelHeight(_ d: Dev) -> CGFloat {
    var h: CGFloat = 92
    for r in d.ranges {
        if r.instance == "temperature" { h += d.isKettle ? 196 : 140 } else { h += 92 }
    }
    if let c = d.color {
        h += 28
        if !c.model.isEmpty { h += 120 }
        if c.hasTK { h += 110 }
        if !c.scenes.isEmpty { h += 34 + CGFloat((c.scenes.count + 2) / 3) * 42 }
    }
    for mc in d.modes { h += 62 + CGFloat((mc.values.count + 2) / 3) * 40 }
    if !d.toggles.isEmpty { h += 30 + CGFloat(d.toggles.count) * 38 }
    if !d.props.isEmpty { h += 30 + CGFloat(d.props.count) * 38 }
    return Swift.min(560, h)
}

/// высота содержимого (чтобы окно было ровно по размеру, без пустоты)
struct HKey: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = Swift.max(value, nextValue()) }
}

extension View {
    func measure(_ m: HomeModel, _ key: String) -> some View {
        return self
            .background(GeometryReader { g in Color.clear.preference(key: HKey.self, value: g.size.height) })
            .onPreferenceChange(HKey.self) { v in m.setHeight(key, v) }
    }
}

/// быстрые настройки — открываются при наведении на плитку
struct QuickPanel: View {
    let id: String
    @ObservedObject var m: HomeModel

    var body: some View {
        Group {
            if let d = m.device(id) {
                let lit = (d.on ?? false) && d.online
                ScrollView {
                    VStack(spacing: 10) {
                        HStack(spacing: 12) {
                            DevImage(d: d, size: 52)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(d.name).font(.system(size: 15, weight: .bold)).lineLimit(1)
                                Text(d.busy ? (d.statusLine ?? "") : (d.online ? (d.on == nil ? m.roomName(d) : (lit ? (d.sub.isEmpty ? "Включено" : d.sub) : "Выключено")) : "Не в сети"))
                                    .font(.system(size: 12, weight: d.busy ? .semibold : .regular))
                                    .foregroundColor(d.busy ? heatOrange : .secondary).lineLimit(1)
                            }
                            Spacer()
                            Button(action: { m.toggleFav(d.id) }) {
                                Image(systemName: m.isFav(d.id) ? "star.fill" : "star").font(.system(size: 15, weight: .semibold))
                                    .foregroundColor(m.isFav(d.id) ? lampYellow : Color.secondary).frame(width: 28, height: 28)
                            }.buttonStyle(.plain).focusable(false)
                            if d.online, d.on != nil {
                                PowerButton(on: lit, size: 38, action: { m.setOn(d.id, !(d.on ?? false)) })
                            }
                        }
                        .padding(.bottom, 2)
                        DeviceControls(d: d, m: m)
                    }
                    .padding(14)
                    .measure(m, "q:" + d.id)
                }
                .frame(width: 330, height: Swift.min(560, Swift.max(80, m.heights["q:" + d.id] ?? panelHeight(d))))
            } else {
                Text("…").frame(width: 200, height: 60)
            }
        }
        .background(pageBG)
        .onHover { h in m.panelHover(h) }
    }
}

// MARK: - Карточка устройства (полная)

struct BackBar: View {
    let title: String
    let action: () -> Void
    var star: Bool? = nil
    var onStar: (() -> Void)? = nil

    var body: some View {
        HStack {
            Button(action: action) {
                HStack(spacing: 4) {
                    Image(systemName: "chevron.left").font(.system(size: 14, weight: .bold))
                    Text("Назад").font(.system(size: 14, weight: .semibold))
                }.foregroundColor(purple)
            }.buttonStyle(.plain).focusable(false)
            Spacer()
            Text(title).font(.system(size: 15, weight: .bold))
            Spacer()
            if let s = star {
                Button(action: { onStar?() }) {
                    HStack(spacing: 4) {
                        Image(systemName: s ? "star.fill" : "star").font(.system(size: 15, weight: .semibold))
                            .foregroundColor(s ? lampYellow : Color.secondary)
                    }
                    .frame(width: 60, alignment: .trailing)
                }.buttonStyle(.plain).focusable(false).help(s ? "Убрать из избранного" : "Добавить в избранное")
            } else {
                Color.clear.frame(width: 60, height: 1)
            }
        }
        .padding(.horizontal, 16).padding(.top, 16).padding(.bottom, 6)
    }
}

struct DetailView: View {
    let d: Dev
    @ObservedObject var m: HomeModel

    func status(_ lit: Bool) -> String {
        if d.busy { return d.statusLine ?? "Работает" }
        if !d.online { return "Не в сети" }
        if d.on == nil { return d.isStation ? "Умная колонка с Алисой" : catFor(d.cat).title }
        if !lit { return "Выключено" }
        if let s = d.statusLine { return s }
        let bits = tileBits(d).map { $0.text }.filter { !$0.isEmpty }
        return bits.isEmpty ? "Включено" : bits.joined(separator: " · ")
    }

    var body: some View {
        let lit = (d.on ?? false) && d.online
        let rich = false
        VStack(spacing: 0) {
            HStack {
                Button(action: { m.closeDetail() }) {
                    HStack(spacing: 4) {
                        Image(systemName: "chevron.left").font(.system(size: 14, weight: .bold))
                        Text("Назад").font(.system(size: 14, weight: .semibold))
                    }
                    .foregroundColor(purple)
                    .frame(width: 80, alignment: .leading)
                    .contentShape(Rectangle())
                }.buttonStyle(.plain).focusable(false).keyboardShortcut(.cancelAction)
                Spacer()
                Text(m.roomName(d)).font(.system(size: 14, weight: .bold))
                Spacer()
                Button(action: { m.toggleFav(d.id) }) {
                    Image(systemName: m.isFav(d.id) ? "star.fill" : "star").font(.system(size: 15, weight: .semibold))
                        .foregroundColor(m.isFav(d.id) ? lampYellow : Color.secondary).frame(width: 80, height: 28, alignment: .trailing)
                }.buttonStyle(.plain).focusable(false).help(m.isFav(d.id) ? "Убрать из избранного" : "Добавить в избранное")
            }
            .padding(.horizontal, 18).padding(.top, 16).padding(.bottom, 8)
            ScrollView {
                VStack(spacing: 14) {
                    if rich {
                        ZStack(alignment: .bottomTrailing) {
                            DevImage(d: d, size: 112)
                            if d.busy {
                                BusyRing(progress: d.progress).frame(width: 118, height: 118)
                                FlameBadge().offset(x: 6, y: 6)
                            }
                        }
                        .frame(width: 120, height: 120)
                        Text(d.name).font(.system(size: 21, weight: .bold)).multilineTextAlignment(.center)
                        Text(status(lit)).font(.system(size: 13, weight: d.busy ? .semibold : .regular))
                            .foregroundColor(d.busy ? heatOrange : .secondary).lineLimit(2).multilineTextAlignment(.center)
                        if d.online, d.on != nil {
                            BigPower(on: lit, action: { m.setOn(d.id, !(d.on ?? false)) })
                        }
                    } else {
                        // простое устройство — компактно в одну строку
                        HStack(spacing: 14) {
                            ZStack(alignment: .bottomTrailing) {
                                DevImage(d: d, size: 76)
                                if d.busy {
                                    BusyRing(progress: d.progress).frame(width: 80, height: 80)
                                    FlameBadge().offset(x: 5, y: 5)
                                }
                            }
                            .frame(width: 80, height: 80)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(d.name).font(.system(size: 19, weight: .bold)).lineLimit(2)
                                Text(status(lit)).font(.system(size: 13, weight: d.busy ? .semibold : .regular))
                                    .foregroundColor(d.busy ? heatOrange : (d.online ? Color.secondary : offRed)).lineLimit(2)
                            }
                            Spacer(minLength: 6)
                            if d.online, d.on != nil {
                                BigPower(on: lit, action: { m.setOn(d.id, !(d.on ?? false)) })
                            }
                        }
                        .padding(14)
                        .background(ZStack {
                            RoundedRectangle(cornerRadius: 20, style: .continuous).fill(tileBG)
                            if let a = accentOf(d) { SoftLight(color: a) }
                        })
                    }
                    DeviceControls(d: d, m: m)
                }
                .padding(.horizontal, 16).padding(.bottom, 20).padding(.top, 2)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(pageBG)
    }
}

// MARK: - Статистика

struct Series: Identifiable {
    var id: String
    var dev: Dev
    var inst: String
    var points: [[Double]]
}

func metricColor(_ i: String) -> Color {
    switch i {
    case "temperature": return Color(red: 1.0, green: 0.5, blue: 0.25)
    case "humidity": return Color(red: 0.2, green: 0.6, blue: 1.0)
    case "co2_level": return Color(red: 0.35, green: 0.75, blue: 0.45)
    case "power": return Color(red: 0.95, green: 0.75, blue: 0.1)
    default: return purple
    }
}

func metricSymbol(_ i: String) -> String {
    switch i {
    case "temperature": return "thermometer.medium"
    case "humidity": return "humidity.fill"
    case "co2_level": return "aqi.medium"
    case "power": return "bolt.fill"
    case "pressure": return "gauge.medium"
    default: return "chart.xyaxis.line"
    }
}

/// оценка «комфортно / сухо / душно»
func comfort(_ i: String, _ v: Double) -> (String, Color)? {
    switch i {
    case "temperature":
        if v < 19 { return ("прохладно", Color(red: 0.3, green: 0.6, blue: 1)) }
        if v > 26 { return ("жарко", Color(red: 1, green: 0.45, blue: 0.3)) }
        return ("комфортно", Color(red: 0.25, green: 0.7, blue: 0.4))
    case "humidity":
        if v < 35 { return ("сухо", Color(red: 1, green: 0.6, blue: 0.15)) }
        if v > 65 { return ("влажно", Color(red: 0.3, green: 0.6, blue: 1)) }
        return ("норма", Color(red: 0.25, green: 0.7, blue: 0.4))
    case "co2_level":
        if v > 1200 { return ("душно — проветрите", Color(red: 1, green: 0.4, blue: 0.3)) }
        if v > 800 { return ("пора проветрить", Color(red: 1, green: 0.6, blue: 0.15)) }
        return ("свежо", Color(red: 0.25, green: 0.7, blue: 0.4))
    default: return nil
    }
}

func fmtMetric(_ i: String, _ v: Double) -> String {
    switch i {
    case "temperature": return Dev.num((v * 10).rounded() / 10) + "°"
    case "humidity": return String(Int(v.rounded())) + "%"
    case "co2_level": return String(Int(v.rounded())) + " ppm"
    case "power": return String(Int(v.rounded())) + " Вт"
    default: return Dev.num((v * 10).rounded() / 10)
    }
}

/// усреднение по интервалам, чтобы график был гладким
func buckets(_ pts: [[Double]], from: Double, to: Double, step: Double) -> [(Double, Double)] {
    var sums: [Int: (Double, Int)] = [:]
    for p in pts where p[0] >= from && p[0] <= to {
        let k = Int((p[0] - from) / step)
        let s = sums[k] ?? (0, 0)
        sums[k] = (s.0 + p[1], s.1 + 1)
    }
    return sums.keys.sorted().map { k in (from + (Double(k) + 0.5) * step, sums[k]!.0 / Double(sums[k]!.1)) }
}

/// положение курсора над графиком (доля ширины); у каждого графика своё, чтобы не перерисовывать всё окно
final class ScrubState: ObservableObject {
    @Published var f: Double? = nil
}

/// кэш форматтеров дат: создавать их на каждый кадр при наведении дорого
var dfmtCache: [String: DateFormatter] = [:]
func dfmt(_ f: String) -> DateFormatter {
    if let x = dfmtCache[f] { return x }
    let d = DateFormatter()
    d.locale = Locale(identifier: "ru_RU")
    d.dateFormat = f
    dfmtCache[f] = d
    return d
}

/// шаг усреднения точек по длине окна
func stepFor(_ span: Double) -> Double {
    if span <= 1.6 * 86400 { return 600 }
    if span <= 4 * 86400 { return 1800 }
    if span <= 8.5 * 86400 { return 7200 }
    if span <= 45 * 86400 { return 6 * 3600 }
    if span <= 400 * 86400 { return 86400 }
    return 7 * 86400
}

/// отметки времени на оси и формат подписи — по длине окна
func chartTicks(from: Double, to: Double) -> ([Double], String) {
    let span = to - from
    let cal = Calendar.current
    let tz = Double(TimeZone.current.secondsFromGMT())
    var out: [Double] = []
    if span <= 40 * 3600 {
        let hrs: Double = span <= 8 * 3600 ? 1 : (span <= 14 * 3600 ? 2 : (span <= 30 * 3600 ? 4 : 6))
        let u = hrs * 3600
        var t = ceil((from + tz) / u) * u - tz
        while t < to { if t > from { out.append(t) }; t += u }
        return (out, "HH:mm")
    }
    if span <= 45 * 86400 {
        let k = span <= 9 * 86400 ? 1 : (span <= 16 * 86400 ? 2 : 5)
        var d = cal.startOfDay(for: Date(timeIntervalSince1970: from))
        if d.timeIntervalSince1970 < from { d = cal.date(byAdding: .day, value: 1, to: d) ?? d }
        var i = 0
        while d.timeIntervalSince1970 < to {
            if i % k == 0 { out.append(d.timeIntervalSince1970) }
            i += 1
            guard let n = cal.date(byAdding: .day, value: 1, to: d) else { break }
            d = n
        }
        return (out, span <= 9 * 86400 ? "EE" : "d MMM")
    }
    var d = cal.date(from: cal.dateComponents([.year, .month], from: Date(timeIntervalSince1970: from))) ?? Date(timeIntervalSince1970: from)
    if d.timeIntervalSince1970 < from { d = cal.date(byAdding: .month, value: 1, to: d) ?? d }
    while d.timeIntervalSince1970 < to {
        out.append(d.timeIntervalSince1970)
        guard let n = cal.date(byAdding: .month, value: 1, to: d) else { break }
        d = n
    }
    return (out, span > 400 * 86400 ? "LLL yy" : "LLL")
}

/// формат подсказки при наведении
func tipFormat(_ span: Double) -> String {
    if span <= 1.6 * 86400 { return "HH:mm" }
    if span <= 9 * 86400 { return "EE, d MMM, HH:mm" }
    if span <= 45 * 86400 { return "d MMM, HH:mm" }
    return "d MMM yyyy"
}

/// обычный интервал между записями: по нему определяем, где данных не было
func medianSpacing(_ p: [[Double]]) -> Double {
    if p.count < 3 { return 300 }
    var d: [Double] = []
    for i in 1..<p.count { d.append(p[i][0] - p[i - 1][0]) }
    d.sort()
    return d[d.count / 2]
}

/// разрываем линию там, где виджет не собирал данные (выключен или спал)
func chartSegments(_ pts: [(Double, Double)], gap: Double) -> [[(Double, Double)]] {
    var out: [[(Double, Double)]] = []
    var cur: [(Double, Double)] = []
    for p in pts {
        if let l = cur.last, p.0 - l.0 > gap { out.append(cur); cur = [] }
        cur.append(p)
    }
    if !cur.isEmpty { out.append(cur) }
    return out
}

struct LineChart: View {
    let pts: [(Double, Double)]
    let from: Double
    let to: Double
    let color: Color
    let inst: String
    let gap: Double
    let live: Bool
    let hasAny: Bool
    @ObservedObject var sc: ScrubState

    func clean(_ s: String) -> String { return s.replacingOccurrences(of: ".", with: "") }

    func nearest(_ t: Double) -> (Double, Double)? {
        var best: (Double, Double)? = nil
        for p in pts {
            if let b = best { if abs(p.0 - t) < abs(b.0 - t) { best = p } } else { best = p }
        }
        return best
    }

    /// подписи не должны налезать друг на друга и на «сейчас»
    func thin(_ ticks: [Double], _ W: CGFloat) -> [Double] {
        var out: [Double] = []
        var last: CGFloat = -100
        let right: CGFloat = live ? W - 56 : W - 18
        for t in ticks {
            let x = CGFloat((t - from) / Swift.max(1, to - from)) * W
            if x < 18 || x > right { continue }
            if x - last >= 40 { out.append(t); last = x }
        }
        return out
    }

    var body: some View {
        let vals = pts.map { $0.1 }
        let lo0 = vals.min() ?? 0, hi0 = vals.max() ?? 1
        let pad = Swift.max((hi0 - lo0) * 0.15, inst == "temperature" ? 0.5 : 2)
        let lo = lo0 - pad, hi = hi0 + pad
        let tk = chartTicks(from: from, to: to)
        let tfmt = tk.1
        let tipF = tipFormat(to - from)
        let segs = chartSegments(pts, gap: gap)
        VStack(spacing: 2) {
            GeometryReader { g in
                let W = g.size.width, H = g.size.height
                let shown = thin(tk.0, W)
                let xy: (Double, Double) -> CGPoint = { t, v in
                    CGPoint(x: CGFloat((t - from) / Swift.max(1, to - from)) * W,
                            y: H - CGFloat((v - lo) / Swift.max(0.001, hi - lo)) * H)
                }
                ZStack(alignment: .topLeading) {
                    ForEach(0..<3) { k in
                        Path { p in
                            let y = H * CGFloat(k + 1) / 4
                            p.move(to: CGPoint(x: 0, y: y)); p.addLine(to: CGPoint(x: W, y: y))
                        }.stroke(Color.primary.opacity(0.06), style: StrokeStyle(lineWidth: 1, dash: [3, 4]))
                    }
                    ForEach(shown, id: \.self) { t in
                        Path { p in
                            let x = xy(t, lo).x
                            p.move(to: CGPoint(x: x, y: 0)); p.addLine(to: CGPoint(x: x, y: H))
                        }.stroke(Color.primary.opacity(0.05), lineWidth: 1)
                    }
                    if pts.count > 1 {
                        ForEach(0..<segs.count, id: \.self) { k in
                            let sg = segs[k]
                            if sg.count > 1 {
                                Path { p in
                                    p.move(to: CGPoint(x: xy(sg[0].0, sg[0].1).x, y: H))
                                    for q in sg { p.addLine(to: xy(q.0, q.1)) }
                                    p.addLine(to: CGPoint(x: xy(sg[sg.count - 1].0, 0).x, y: H))
                                    p.closeSubpath()
                                }
                                .fill(LinearGradient(colors: [color.opacity(0.28), color.opacity(0.02)], startPoint: .top, endPoint: .bottom))
                                Path { p in
                                    p.move(to: xy(sg[0].0, sg[0].1))
                                    for q in sg.dropFirst() { p.addLine(to: xy(q.0, q.1)) }
                                }
                                .stroke(color, style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                            } else if sg.count == 1 {
                                Circle().fill(color).frame(width: 4, height: 4).position(xy(sg[0].0, sg[0].1))
                            }
                        }
                        if sc.f == nil && live {
                            let lp = xy(pts[pts.count - 1].0, pts[pts.count - 1].1)
                            Circle().fill(color).frame(width: 8, height: 8)
                                .overlay(Circle().stroke(Color.white, lineWidth: 2))
                                .position(lp)
                        }
                        Text(fmtMetric(inst, hi0)).font(.system(size: 9, weight: .medium)).foregroundColor(.secondary).offset(x: 2, y: 0)
                        Text(fmtMetric(inst, lo0)).font(.system(size: 9, weight: .medium)).foregroundColor(.secondary).offset(x: 2, y: H - 12)
                    } else {
                        Text(hasAny ? "Нет данных за этот период" : "Данные копятся — график появится через полчаса")
                            .font(.system(size: 11)).foregroundColor(.secondary)
                            .frame(width: W, height: H)
                    }
                    // ползунок: линия, точка на графике и подсказка со временем и значением
                    if let f = sc.f, pts.count > 1 {
                        let t = from + f * (to - from)
                        let cx = CGFloat(f) * W
                        let near = nearest(t)
                        let has = near.map { abs($0.0 - t) <= gap } ?? false
                        Path { p in p.move(to: CGPoint(x: cx, y: 0)); p.addLine(to: CGPoint(x: cx, y: H)) }
                            .stroke(color.opacity(0.6), style: StrokeStyle(lineWidth: 1, dash: [3, 3]))
                        if has, let n = near {
                            Circle().fill(color).frame(width: 11, height: 11)
                                .overlay(Circle().stroke(Color.white, lineWidth: 2.5))
                                .position(xy(n.0, n.1))
                        }
                        VStack(spacing: 1) {
                            Text(has ? fmtMetric(inst, near?.1 ?? 0) : "нет данных")
                                .font(.system(size: 12, weight: .bold)).monospacedDigit()
                            Text(clean(dfmt(tipF).string(from: Date(timeIntervalSince1970: has ? (near?.0 ?? t) : t))))
                                .font(.system(size: 9.5)).foregroundColor(.secondary)
                        }
                        .padding(.horizontal, 9).padding(.vertical, 4)
                        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color(NSColor.windowBackgroundColor))
                            .shadow(color: Color.black.opacity(0.18), radius: 3, x: 0, y: 1))
                        .fixedSize()
                        .position(x: Swift.min(Swift.max(cx, 52), W - 52), y: 20)
                    }
                }
                .frame(width: W, height: H)
                .contentShape(Rectangle())
                .onContinuousHover { phase in
                    switch phase {
                    case .active(let loc):
                        sc.f = Double(Swift.min(1, Swift.max(0, loc.x / Swift.max(1, W))))
                    case .ended:
                        sc.f = nil
                    }
                }
            }
            .frame(height: 92)
            // ось времени: точки и подписи
            GeometryReader { g in
                let W = g.size.width
                let shown = thin(tk.0, W)
                ZStack(alignment: .topLeading) {
                    ForEach(shown, id: \.self) { t in
                        VStack(spacing: 2) {
                            Circle().fill(Color.secondary.opacity(0.55)).frame(width: 3, height: 3)
                            Text(clean(dfmt(tfmt).string(from: Date(timeIntervalSince1970: t))))
                                .font(.system(size: 9, weight: .medium)).foregroundColor(.secondary).fixedSize()
                        }
                        .position(x: CGFloat((t - from) / Swift.max(1, to - from)) * W, y: 11)
                    }
                    if live {
                        VStack(spacing: 2) {
                            Circle().fill(color).frame(width: 3, height: 3)
                            Text("сейчас").font(.system(size: 9, weight: .semibold)).foregroundColor(color).fixedSize()
                        }
                        .position(x: W - 20, y: 11)
                    }
                }
            }
            .frame(height: 24)
        }
    }
}

struct StatCard: View {
    let s: Series
    @ObservedObject var m: HomeModel
    var grouped = false

    var body: some View {
        let now = Date().timeIntervalSince1970
        let win = m.statsWindow()
        let from = win.0, to = win.1
        let step = stepFor(to - from)
        let pts = buckets(s.points, from: from, to: to, step: step)
        let rawPts = s.points.filter { $0[0] >= from && $0[0] <= to }
        let raw = rawPts.map { $0[1] }
        let isNow = from <= now && now <= to + 60
        let avgV: Double? = raw.isEmpty ? nil : raw.reduce(0, +) / Double(raw.count)
        let curV = s.dev.props.first(where: { $0.instance == s.inst })?.value ?? raw.last
        let cur: Double? = isNow ? curV : avgV
        let col = metricColor(s.inst)
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: metricSymbol(s.inst)).font(.system(size: 13, weight: .semibold)).foregroundColor(col)
                VStack(alignment: .leading, spacing: 1) {
                    Text(propTitle(s.inst)).font(.system(size: 13, weight: .bold))
                    if !grouped {
                        Text(s.dev.name + " · " + m.roomName(s.dev)).font(.system(size: 11)).foregroundColor(.secondary).lineLimit(1)
                    }
                }
                Spacer()
                if let c = cur {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(fmtMetric(s.inst, c)).font(.system(size: 20, weight: .bold)).monospacedDigit()
                        if !isNow { Text("в среднем").font(.system(size: 10)).foregroundColor(.secondary) }
                        if let cf = comfort(s.inst, c) {
                            Text(cf.0).font(.system(size: 10, weight: .semibold)).foregroundColor(cf.1)
                                .padding(.horizontal, 6).padding(.vertical, 1)
                                .background(Capsule().fill(cf.1.opacity(0.15)))
                        }
                    }
                }
            }
            LineChart(pts: pts, from: from, to: to, color: col, inst: s.inst,
                      gap: Swift.max(step * 3, medianSpacing(rawPts) * 2.5), live: win.2, hasAny: !s.points.isEmpty, sc: m.scrub(s.id))
            if !raw.isEmpty {
                HStack(spacing: 0) {
                    StatPill(title: "мин", value: fmtMetric(s.inst, raw.min() ?? 0))
                    StatPill(title: "среднее", value: fmtMetric(s.inst, raw.reduce(0, +) / Double(raw.count)))
                    StatPill(title: "макс", value: fmtMetric(s.inst, raw.max() ?? 0))
                    if let a = pts.first?.1, let b = pts.last?.1, pts.count > 1 {
                        let d = b - a
                        StatPill(title: "изменение", value: (d >= 0 ? "+" : "−") + fmtMetric(s.inst, abs(d)))
                    }
                }
            }
        }
        .card()
    }
}

struct StatPill: View {
    let title: String
    let value: String

    var body: some View {
        VStack(spacing: 1) {
            Text(value).font(.system(size: 13, weight: .semibold)).monospacedDigit()
            Text(title).font(.system(size: 10)).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}

struct NavBtn: View {
    let symbol: String
    let on: Bool
    let act: () -> Void

    var body: some View {
        Button(action: act) {
            Image(systemName: symbol).font(.system(size: 13, weight: .bold))
                .foregroundColor(on ? purple : Color.secondary.opacity(0.4))
                .frame(width: 40, height: 36)
                .background(Capsule().fill(Color.primary.opacity(0.045)))
                .contentShape(Capsule())
        }.buttonStyle(.plain).focusable(false).disabled(!on)
    }
}

/// стрелки по бокам, название отрезка и заметная кнопка календаря
struct StatsNav: View {
    @ObservedObject var m: HomeModel

    var body: some View {
        let live = m.statsWindow().2
        VStack(spacing: 6) {
            HStack(spacing: 8) {
                NavBtn(symbol: "chevron.left", on: m.canBack, act: { m.shiftStats(-1) })
                Text(m.statsTitle()).font(.system(size: 13.5, weight: .bold)).lineLimit(1).minimumScaleFactor(0.8)
                    .frame(maxWidth: .infinity)
                NavBtn(symbol: "chevron.right", on: m.canForward, act: { m.shiftStats(1) })
                Button(action: { m.togglePicker() }) {
                    HStack(spacing: 5) {
                        Image(systemName: m.showPicker ? "xmark" : "calendar").font(.system(size: 12, weight: .bold))
                        Text(m.showPicker ? "Закрыть" : "Календарь").font(.system(size: 12.5, weight: .semibold))
                    }
                    .foregroundColor(.white)
                    .padding(.horizontal, 13).frame(height: 36)
                    .background(Capsule().fill(purple))
                    .shadow(color: purple.opacity(0.35), radius: 4, x: 0, y: 2)
                    .contentShape(Capsule())
                }.buttonStyle(.plain).focusable(false).help("Выбрать день или период")
            }
            if !live {
                Button(action: { m.statsNow() }) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.uturn.forward").font(.system(size: 10, weight: .bold))
                        Text("Вернуться к текущему времени").font(.system(size: 11.5, weight: .medium))
                    }.foregroundColor(purple)
                }.buttonStyle(.plain).focusable(false)
            }
        }
    }
}

/// календарь: нажмите на день — откроется он; режим «Период» — нажмите первый и последний день
struct StatsPicker: View {
    @ObservedObject var m: HomeModel

    func chip(_ t: String, _ act: @escaping () -> Void) -> some View {
        return Button(action: act) {
            Text(t).font(.system(size: 11.5, weight: .semibold)).foregroundColor(purple)
                .padding(.horizontal, 10).padding(.vertical, 5)
                .background(Capsule().fill(purple.opacity(0.12)))
                .contentShape(Capsule())
        }.buttonStyle(.plain).focusable(false)
    }

    func selection(_ cal: Calendar) -> (Date?, Date?) {
        if let st = m.rangeStart { return (st, st) }
        if m.statsPeriod == 4 {
            return (cal.startOfDay(for: Swift.min(m.customFrom, m.customTo)), cal.startOfDay(for: Swift.max(m.customFrom, m.customTo)))
        }
        let w = m.statsWindow()
        if !w.2 {
            return (cal.startOfDay(for: Date(timeIntervalSince1970: w.0)), cal.startOfDay(for: Date(timeIntervalSince1970: w.1 - 1)))
        }
        return (nil, nil)
    }

    var body: some View {
        let cal = Calendar.current
        let today = cal.startOfDay(for: Date())
        let first = cal.startOfDay(for: Date(timeIntervalSince1970: m.historyStart))
        let monthStart = cal.date(from: cal.dateComponents([.year, .month], from: m.calMonth)) ?? today
        let nDays = cal.range(of: .day, in: .month, for: monthStart)?.count ?? 30
        let wd = (cal.component(.weekday, from: monthStart) + 5) % 7
        let rows = (wd + nDays + 6) / 7
        let has = m.daysWithData(monthStart)
        let firstMonth = cal.date(from: cal.dateComponents([.year, .month], from: first)) ?? first
        let thisMonth = cal.date(from: cal.dateComponents([.year, .month], from: today)) ?? today
        let sel = selection(cal)
        let selA = sel.0
        let selB = sel.1
        let title = dfmt("LLLL yyyy").string(from: monthStart)
        VStack(spacing: 10) {
            HStack(spacing: 6) {
                ForEach(0..<2) { i in
                    Button(action: { m.pickMode = i; m.rangeStart = nil }) {
                        Text(["Один день", "Период"][i]).font(.system(size: 12.5, weight: .semibold))
                            .frame(maxWidth: .infinity).padding(.vertical, 7)
                            .background(Capsule().fill(m.pickMode == i ? purple : Color.primary.opacity(0.06)))
                            .foregroundColor(m.pickMode == i ? Color.white : Color.primary)
                            .contentShape(Capsule())
                    }.buttonStyle(.plain).focusable(false)
                }
            }
            Text(m.pickMode == 0 ? "Нажмите на день, чтобы посмотреть его"
                 : (m.rangeStart == nil ? "Нажмите на первый день периода" : "Теперь нажмите на последний день"))
                .font(.system(size: 11.5)).foregroundColor(.secondary)
            HStack {
                NavBtn(symbol: "chevron.left", on: monthStart > firstMonth,
                       act: { m.calMonth = cal.date(byAdding: .month, value: -1, to: monthStart) ?? monthStart })
                Text(title.prefix(1).uppercased() + title.dropFirst()).font(.system(size: 14, weight: .bold)).frame(maxWidth: .infinity)
                NavBtn(symbol: "chevron.right", on: monthStart < thisMonth,
                       act: { m.calMonth = cal.date(byAdding: .month, value: 1, to: monthStart) ?? monthStart })
            }
            HStack(spacing: 0) {
                ForEach(0..<7) { c in
                    Text(["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"][c]).font(.system(size: 10.5, weight: .semibold))
                        .foregroundColor(c >= 5 ? Color(red: 1, green: 0.45, blue: 0.4) : Color.secondary)
                        .frame(maxWidth: .infinity)
                }
            }
            VStack(spacing: 2) {
                ForEach(0..<rows, id: \.self) { r in
                    HStack(spacing: 0) {
                        ForEach(0..<7, id: \.self) { c in
                            let n = r * 7 + c - wd + 1
                            if n >= 1 && n <= nDays {
                                let date = cal.date(byAdding: .day, value: n - 1, to: monthStart) ?? monthStart
                                let ok = date >= first && date <= today
                                let inR = (selA != nil && selB != nil) ? (date >= selA! && date <= selB!) : false
                                let edge = (selA != nil && date == selA!) || (selB != nil && date == selB!)
                                Button(action: { if ok { m.calTap(date) } }) {
                                    ZStack {
                                        if inR && !edge {
                                            Rectangle().fill(purple.opacity(0.16)).frame(height: 32)
                                        }
                                        if edge {
                                            Circle().fill(purple).frame(width: 32, height: 32)
                                        }
                                        VStack(spacing: 1) {
                                            Text("\(n)").font(.system(size: 13, weight: date == today ? .bold : .medium)).monospacedDigit()
                                                .foregroundColor(edge ? Color.white : (ok ? (date == today ? purple : Color.primary) : Color.secondary.opacity(0.35)))
                                            Circle().fill(has.contains(n) && ok ? (edge ? Color.white : purple.opacity(0.7)) : Color.clear)
                                                .frame(width: 3.5, height: 3.5)
                                        }
                                    }
                                    .frame(maxWidth: .infinity).frame(height: 36)
                                    .contentShape(Rectangle())
                                }.buttonStyle(.plain).focusable(false).disabled(!ok)
                            } else {
                                Color.clear.frame(maxWidth: .infinity).frame(height: 36)
                            }
                        }
                    }
                }
            }
            HStack(spacing: 6) {
                chip("Вчера", { m.pickDay(cal.date(byAdding: .day, value: -1, to: today) ?? today) })
                chip("Прошлая неделя", {
                    let wdNow = (cal.component(.weekday, from: today) + 5) % 7
                    let mon = cal.date(byAdding: .day, value: -wdNow - 7, to: today) ?? today
                    m.setRange(mon, cal.date(byAdding: .day, value: 6, to: mon) ?? mon)
                })
                chip("Прошлый месяц", {
                    let tm = cal.date(from: cal.dateComponents([.year, .month], from: today)) ?? today
                    let pm = cal.date(byAdding: .month, value: -1, to: tm) ?? tm
                    m.setRange(pm, cal.date(byAdding: .day, value: -1, to: tm) ?? tm)
                })
                Spacer()
            }
            Text("Точка под числом — за этот день есть данные").font(.system(size: 10.5)).foregroundColor(.secondary)
        }
        .card()
    }
}

struct StatsPage: View {
    @ObservedObject var m: HomeModel

    var series: [Series] {
        var out: [Series] = []
        for d in m.allDevices where !d.isKettle {
            for inst in HomeModel.tracked {
                let k = d.id + "|" + inst
                if d.props.contains(where: { $0.instance == inst }) || m.history[k] != nil {
                    out.append(Series(id: k, dev: d, inst: inst, points: m.history[k] ?? []))
                }
            }
        }
        let order = ["temperature": 0, "humidity": 1, "co2_level": 2, "pressure": 3, "power": 4]
        return out.sorted { a, b in
            (order[a.inst] ?? 9, a.dev.name) < (order[b.inst] ?? 9, b.dev.name)
        }
    }

    var body: some View {
        let list = series
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 6) {
                    ForEach(0..<4) { i in
                        Button(action: { m.statsPeriod = i }) {
                            Text(["Сутки", "Неделя", "Месяц", "Год"][i]).font(.system(size: 12, weight: .semibold))
                                .frame(maxWidth: .infinity).padding(.vertical, 6)
                                .background(Capsule().fill(m.statsPeriod == i ? purple.opacity(0.14) : Color.primary.opacity(0.045)))
                                .overlay(Capsule().stroke(m.statsPeriod == i ? purple.opacity(0.85) : Color.clear, lineWidth: 1.5))
                                .foregroundColor(m.statsPeriod == i ? purple : Color.primary)
                                .contentShape(Capsule())
                        }.buttonStyle(.plain).focusable(false)
                    }
                }
                StatsNav(m: m)
                if m.showPicker { StatsPicker(m: m) }
                if list.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "chart.xyaxis.line").font(.system(size: 34)).foregroundColor(.secondary)
                        Text("Нет датчиков температуры, влажности или воздуха").font(.system(size: 13)).foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity).padding(.top, 50)
                } else {
                    // комната → датчик → графики
                    ForEach(m.scopedRooms) { r in
                        let ids = Set(r.devices.map { $0.id })
                        let inRoom = list.filter { ids.contains($0.dev.id) }
                        if !inRoom.isEmpty {
                            let devs = r.devices.filter { d in inRoom.contains { $0.dev.id == d.id } }
                            VStack(alignment: .leading, spacing: 10) {
                                HStack(spacing: 6) {
                                    Text(r.name).font(.system(size: 18, weight: .bold))
                                    Text("\(devs.count) " + (devs.count == 1 ? "датчик" : "датчиков"))
                                        .font(.system(size: 11, weight: .semibold)).foregroundColor(.secondary)
                                }.padding(.top, 6)
                                ForEach(devs) { d in
                                    HStack(spacing: 8) {
                                        DevImage(d: d, size: 24)
                                        Text(d.name).font(.system(size: 14, weight: .semibold))
                                        if !d.online { Text("не в сети").font(.system(size: 11)).foregroundColor(.secondary) }
                                    }.padding(.top, 2).padding(.leading, 2)
                                    ForEach(inRoom.filter { $0.dev.id == d.id }) { s in
                                        StatCard(s: s, m: m, grouped: true)
                                    }
                                }
                            }
                        }
                    }
                    Text("Яндекс не хранит историю показаний, поэтому виджет копит её сам — раз в 5 минут, пока он запущен. История хранится без ограничения по сроку: свежие две недели подробно, более старое — с шагом 30 минут.")
                        .font(.system(size: 11)).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 4)
                }
            }
            .padding(.horizontal, 16).padding(.top, 2).padding(.bottom, 20)
        }
    }
}

// MARK: - Настройки виджета

struct SetRow: View {
    let symbol: String
    let tint: Color
    let title: String
    let sub: String?
    let get: () -> Bool
    let set: (Bool) -> Void

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 8, style: .continuous).fill(tint).frame(width: 30, height: 30)
                Image(systemName: symbol).font(.system(size: 14, weight: .semibold)).foregroundColor(.white)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .medium))
                if let s = sub { Text(s).font(.system(size: 11)).foregroundColor(.secondary) }
            }
            Spacer()
            Toggle("", isOn: Binding<Bool>(get: get, set: set)).toggleStyle(.switch).labelsHidden().controlSize(.small)
        }
        .padding(.vertical, 7)
    }
}

struct BarOption: View {
    let key: String
    let symbol: String
    let title: String
    @ObservedObject var m: HomeModel

    var body: some View {
        let sel = m.barMode == key
        Button(action: { m.setBarMode(key) }) {
            VStack(spacing: 6) {
                Image(systemName: symbol).font(.system(size: 18, weight: .semibold))
                    .foregroundColor(sel ? purple : Color.secondary)
                Text(title).font(.system(size: 11, weight: .semibold)).multilineTextAlignment(.center).lineLimit(2)
                    .foregroundColor(sel ? Color.primary : Color.secondary)
            }
            .frame(maxWidth: .infinity, minHeight: 66)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(sel ? purple.opacity(0.14) : softBtn.opacity(0.6)))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(sel ? purple : Color.clear, lineWidth: 1.5))
            .contentShape(Rectangle())
        }.buttonStyle(.plain).focusable(false)
    }
}

struct DevicePicker: View {
    let list: [Dev]
    @ObservedObject var m: HomeModel

    var body: some View {
        let cur = m.device(m.barDevice)
        Menu {
            ForEach(list) { d in
                Button(d.name + "  ·  " + m.roomName(d)) { m.barDevice = d.id }
            }
        } label: {
            HStack(spacing: 10) {
                if let d = cur { DevImage(d: d, size: 28) }
                Text(cur?.name ?? "Выберите устройство").font(.system(size: 13, weight: .semibold))
                Spacer()
                Image(systemName: "chevron.up.chevron.down").font(.system(size: 11, weight: .semibold)).foregroundColor(.secondary)
            }
        }
        .menuStyle(.borderlessButton)
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(softBtn.opacity(0.6)))
    }
}

struct SectionTitle: View {
    let text: String
    let symbol: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: symbol).font(.system(size: 12, weight: .semibold)).foregroundColor(purple.opacity(0.8))
            Text(text).font(.system(size: 14, weight: .bold))
        }
        .padding(.leading, 4).padding(.top, 4)
    }
}

struct OrderButtons: View {
    let up: Bool
    let down: Bool
    let onUp: () -> Void
    let onDown: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Button(action: onUp) {
                ZStack {
                    Circle().fill(softBtn).frame(width: 26, height: 26)
                    Image(systemName: "chevron.up").font(.system(size: 11, weight: .bold))
                }
            }.buttonStyle(.plain).focusable(false).disabled(!up).opacity(up ? 1 : 0.3)
            Button(action: onDown) {
                ZStack {
                    Circle().fill(softBtn).frame(width: 26, height: 26)
                    Image(systemName: "chevron.down").font(.system(size: 11, weight: .bold))
                }
            }.buttonStyle(.plain).focusable(false).disabled(!down).opacity(down ? 1 : 0.3)
        }
    }
}

struct SettingsView: View {
    @ObservedObject var m: HomeModel
    var onQuit: () -> Void
    let cols = [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)]

    var body: some View {
        let segs = m.barSegments(0)
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    SectionTitle(text: "Версия и обновления", symbol: "arrow.down.circle")
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Мой дом · версия " + appVersion).font(.system(size: 15, weight: .bold))
                                Text("Разработчик: " + appAuthor).font(.system(size: 11)).foregroundColor(.secondary)
                                Text(m.lastUpdateCheck.map { "Проверено " + HomeModel.agoText($0) } ?? "Ещё не проверяли")
                                    .font(.system(size: 11)).foregroundColor(.secondary)
                            }
                            Spacer()
                            Button(action: { m.checkUpdate(manual: true) }) {
                                Text(m.checkingUpdate ? "Проверяю…" : "Проверить обновление")
                                    .font(.system(size: 12, weight: .semibold)).foregroundColor(.white)
                                    .padding(.horizontal, 12).padding(.vertical, 7)
                                    .background(Capsule().fill(purple))
                            }.buttonStyle(.plain).focusable(false).disabled(m.checkingUpdate)
                        }
                        if m.updateAvailable, let t = m.latestTag {
                            Button(action: {
                                if let u = URL(string: m.latestURL ?? "https://github.com/Lenar111/yahome/releases/latest") { NSWorkspace.shared.open(u) }
                            }) {
                                HStack(spacing: 8) {
                                    Image(systemName: "sparkles")
                                    Text("Вышла новая версия " + t + " — открыть релиз").font(.system(size: 12.5, weight: .semibold))
                                    Spacer()
                                    Image(systemName: "arrow.up.right")
                                }
                                .foregroundColor(.white).padding(.horizontal, 12).padding(.vertical, 9)
                                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color(red: 0.2, green: 0.7, blue: 0.4)))
                            }.buttonStyle(.plain).focusable(false)
                            if !m.latestNotes.isEmpty { UpdateNotes(items: m.latestNotes) }
                        } else if let msg = m.updateMsg {
                            Text(msg).font(.system(size: 12)).foregroundColor(.secondary)
                        }
                        Divider()
                        SetRow(symbol: "clock.arrow.circlepath", tint: Color(red: 0.25, green: 0.6, blue: 1), title: "Проверять раз в сутки",
                               sub: "Сам ничего не устанавливает — только покажет ссылку на новый релиз",
                               get: { m.autoUpdateCheck }, set: { m.autoUpdateCheck = $0 })
                    }
                    .card()

                    SectionTitle(text: "Строка меню", symbol: "menubar.rectangle")
                    VStack(alignment: .leading, spacing: 12) {
                        // предпросмотр
                        HStack(spacing: 0) {
                            Spacer()
                            HStack(spacing: 10) {
                                ForEach(Array(segs.enumerated()), id: \.offset) { _, s in
                                    HStack(spacing: 3) {
                                        if !s.0.isEmpty { Image(systemName: s.0).font(.system(size: 12, weight: .medium)) }
                                        if !s.1.isEmpty {
                                            Text(s.1).font(.system(size: 12.5, weight: barTint(s) == nil ? .medium : .semibold)).monospacedDigit()
                                                .foregroundColor(barTint(s, dark: true).map { Color($0) } ?? Color.white)
                                        }
                                    }
                                }
                            }
                            .foregroundColor(.white)
                            .padding(.horizontal, 12).padding(.vertical, 5)
                            .background(Capsule().fill(Color.black.opacity(0.78)))
                            Spacer()
                        }
                        .padding(.vertical, 8)
                        .background(RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(LinearGradient(colors: [Color(red: 0.62, green: 0.68, blue: 0.95), Color(red: 0.86, green: 0.72, blue: 0.95)], startPoint: .leading, endPoint: .trailing).opacity(0.35)))

                        if m.barItems.isEmpty {
                            Text("Пока только значок дома. Добавьте, что показывать рядом.").font(.system(size: 12)).foregroundColor(.secondary)
                        }
                        ForEach(Array(m.barItems.enumerated()), id: \.element) { i, it in
                            let info = m.barItemInfo(it)
                            HStack(spacing: 10) {
                                ZStack {
                                    RoundedRectangle(cornerRadius: 8, style: .continuous).fill(purple.opacity(0.12)).frame(width: 30, height: 30)
                                    Image(systemName: info.0).font(.system(size: 13, weight: .semibold)).foregroundColor(purple)
                                }
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(info.1).font(.system(size: 13, weight: .medium)).lineLimit(1)
                                    if !info.2.isEmpty { Text(info.2).font(.system(size: 11)).foregroundColor(.secondary).lineLimit(1) }
                                }
                                Spacer()
                                OrderButtons(up: i > 0, down: i < m.barItems.count - 1,
                                             onUp: { m.moveBar(it, -1) }, onDown: { m.moveBar(it, 1) })
                                Button(action: { m.removeBar(it) }) {
                                    Image(systemName: "minus.circle.fill").font(.system(size: 17)).foregroundColor(Color(red: 1, green: 0.4, blue: 0.4))
                                }.buttonStyle(.plain).focusable(false).help("Убрать из строки меню")
                            }
                        }
                        Menu {
                            Section("Дом") {
                                Button("Значок дома") { m.addBar("home") }
                                Button("Значок и сколько включено") { m.addBar("home:count") }
                                Button("Сколько горит света") { m.addBar("lights") }
                            }
                            if !m.tempSources.isEmpty {
                                Section("Температура") {
                                    ForEach(m.tempSources) { d in
                                        Button(d.name + " · " + m.roomName(d)) { m.addBar("temp:" + d.id) }
                                    }
                                }
                            }
                            if !m.humSources.isEmpty {
                                Section("Влажность") {
                                    ForEach(m.humSources) { d in
                                        Button(d.name + " · " + m.roomName(d)) { m.addBar("hum:" + d.id) }
                                    }
                                }
                            }
                            if !m.co2Sources.isEmpty {
                                Section("Воздух (CO₂)") {
                                    ForEach(m.co2Sources) { d in
                                        Button(d.name + " · " + m.roomName(d)) { m.addBar("co2:" + d.id) }
                                    }
                                }
                            }
                            Section("Устройства") {
                                ForEach(m.scopedRooms) { r in
                                    Menu(r.name) {
                                        ForEach(r.devices) { d in
                                            Button(d.name) { m.addBar("dev:" + d.id) }
                                        }
                                    }
                                }
                            }
                        } label: {
                            Label("Добавить в строку меню", systemImage: "plus.circle.fill").font(.system(size: 13, weight: .semibold))
                        }
                        .menuStyle(.borderlessButton).fixedSize()
                        .foregroundColor(purple)
                        .padding(.top, 2)
                    }
                    .card()

                    SectionTitle(text: "Процессы и уведомления", symbol: "bell.badge")
                    VStack(spacing: 0) {
                        SetRow(symbol: "flame.fill", tint: heatOrange, title: "Показывать процесс в строке меню",
                               sub: "Нагрев чайника и уборка — с анимацией и градусами",
                               get: { m.barBusy }, set: { m.barBusy = $0 })
                        Divider().padding(.leading, 42)
                        SetRow(symbol: "bell.fill", tint: Color(red: 1, green: 0.42, blue: 0.45), title: "Звук, когда чайник готов", sub: nil,
                               get: { m.doneSound }, set: { m.doneSound = $0 })
                    }
                    .card()

                    SectionTitle(text: "Окно и наведение", symbol: "macwindow")
                    VStack(spacing: 0) {
                        SetRow(symbol: "cursorarrow.rays", tint: purple, title: "Открывать и закрывать при наведении",
                               sub: "Окно раскрывается от курсора на значке и само прячется, когда курсор уходит",
                               get: { m.hoverOpen }, set: { m.hoverOpen = $0 })
                        Divider().padding(.leading, 42)
                        SetRow(symbol: "slider.horizontal.3", tint: Color(red: 0.25, green: 0.6, blue: 1), title: "Режимы при наведении на плитку",
                               sub: "Появляются, если подержать курсор на устройстве секунду",
                               get: { m.hoverTiles }, set: { m.hoverTiles = $0 })
                        Divider().padding(.leading, 42)
                        SetRow(symbol: "wifi.slash", tint: Color(red: 0.6, green: 0.62, blue: 0.68), title: "Показывать устройства не в сети", sub: nil,
                               get: { m.showOffline }, set: { m.showOffline = $0 })
                    }
                    .card()

                    SectionTitle(text: "Порядок комнат", symbol: "square.grid.2x2")
                    VStack(spacing: 0) {
                        ForEach(Array(m.scopedRooms.enumerated()), id: \.element.id) { i, r in
                            HStack(spacing: 10) {
                                Image(systemName: "line.3.horizontal").font(.system(size: 12)).foregroundColor(.secondary)
                                Text(r.name).font(.system(size: 13, weight: .medium))
                                Text("\(r.devices.count)").font(.system(size: 11)).foregroundColor(.secondary)
                                Spacer()
                                OrderButtons(up: i > 0, down: i < m.scopedRooms.count - 1,
                                             onUp: { m.moveRoom(r.id, -1) }, onDown: { m.moveRoom(r.id, 1) })
                            }
                            .padding(.vertical, 6)
                            if i < m.scopedRooms.count - 1 { Divider() }
                        }
                        if !m.roomOrder.isEmpty {
                            Button(action: { m.resetRoomOrder() }) {
                                Text("Вернуть по алфавиту").font(.system(size: 12, weight: .semibold)).foregroundColor(purple)
                            }.buttonStyle(.plain).focusable(false).padding(.top, 8)
                        }
                    }
                    .card()

                    SectionTitle(text: "Избранное", symbol: "star")
                    VStack(alignment: .leading, spacing: 0) {
                        let fl = m.favDevices
                        if fl.isEmpty {
                            Text("Нажмите ☆ в карточке устройства или правой кнопкой по плитке → «Добавить в избранное». Избранное появится первым на главном экране.")
                                .font(.system(size: 12)).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                        ForEach(Array(fl.enumerated()), id: \.element.id) { i, d in
                            HStack(spacing: 10) {
                                DevImage(d: d, size: 28)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(d.name).font(.system(size: 13, weight: .medium)).lineLimit(1)
                                    Text(m.roomName(d)).font(.system(size: 11)).foregroundColor(.secondary)
                                }
                                Spacer()
                                OrderButtons(up: i > 0, down: i < fl.count - 1,
                                             onUp: { m.moveFav(d.id, -1) }, onDown: { m.moveFav(d.id, 1) })
                                Button(action: { m.toggleFav(d.id) }) {
                                    Image(systemName: "xmark.circle.fill").font(.system(size: 15)).foregroundColor(.secondary)
                                }.buttonStyle(.plain).focusable(false)
                            }
                            .padding(.vertical, 5)
                            if i < fl.count - 1 { Divider() }
                        }
                    }
                    .card()

                    SectionTitle(text: "Аккаунт", symbol: "person.crop.circle")
                    VStack(spacing: 10) {
                        HStack {
                            Image(systemName: "house.fill").foregroundColor(purple)
                            Text(m.householdName).font(.system(size: 13, weight: .semibold))
                            Spacer()
                            Text("\(m.allDevices.count) устройств").font(.system(size: 12)).foregroundColor(.secondary)
                        }
                        HStack(spacing: 8) {
                            Button(action: { m.refresh() }) {
                                Label("Обновить", systemImage: "arrow.clockwise").font(.system(size: 12, weight: .semibold))
                                    .frame(maxWidth: .infinity).padding(.vertical, 8)
                                    .background(Capsule().fill(softBtn))
                            }.buttonStyle(.plain).focusable(false)
                            Button(action: { m.logout() }) {
                                Label("Выйти", systemImage: "rectangle.portrait.and.arrow.right").font(.system(size: 12, weight: .semibold))
                                    .frame(maxWidth: .infinity).padding(.vertical, 8)
                                    .background(Capsule().fill(softBtn))
                            }.buttonStyle(.plain).focusable(false)
                            Button(action: onQuit) {
                                Label("Закрыть", systemImage: "xmark").font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(Color(red: 1, green: 0.35, blue: 0.35))
                                    .frame(maxWidth: .infinity).padding(.vertical, 8)
                                    .background(Capsule().fill(softBtn))
                            }.buttonStyle(.plain).focusable(false)
                        }
                    }
                    .card()

                }
                .padding(.horizontal, 16).padding(.bottom, 20)
            }
        }
    }
}

// MARK: - Вход

struct LoginView: View {
    @ObservedObject var m: HomeModel

    var body: some View {
        VStack(spacing: 14) {
            Spacer()
            ZStack {
                Circle().fill(LinearGradient(colors: [purple, Color(red: 0.35, green: 0.55, blue: 1)], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 92, height: 92)
                Image(systemName: "house.fill").font(.system(size: 40)).foregroundColor(.white)
            }
            Text("Умный дом Яндекса").font(.system(size: 20, weight: .bold))
            Text("Войдите через Яндекс один раз. Виджет получит доступ только к устройствам и сценариям.")
                .font(.system(size: 13)).foregroundColor(.secondary).multilineTextAlignment(.center).padding(.horizontal, 40)
            if let e = m.error {
                Text(e).font(.system(size: 12)).foregroundColor(.orange)
            }
            Button(action: { m.login() }) {
                Text(m.waiting ? "Жду подтверждения в браузере…" : "Войти через Яндекс")
                    .font(.system(size: 14, weight: .semibold)).foregroundColor(Color.white)
                    .padding(.horizontal, 24).padding(.vertical, 11)
                    .background(Capsule().fill(purple))
            }.buttonStyle(.plain).focusable(false)
            Button(action: { m.showManual.toggle() }) {
                Text("Не получается войти?").font(.system(size: 12)).foregroundColor(.secondary)
            }.buttonStyle(.plain).focusable(false)
            if m.showManual {
                VStack(spacing: 8) {
                    Text("Вставьте сюда ссылку или токен со страницы Яндекса").font(.system(size: 11)).foregroundColor(.secondary)
                    TextField("access_token=…", text: $m.manual).textFieldStyle(.roundedBorder)
                    Button("Готово") { m.acceptManual() }
                }.padding(.horizontal, 40)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

struct TabButton: View {
    let symbol: String
    let title: String
    let on: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 3) {
                Image(systemName: symbol).font(.system(size: 18, weight: .semibold))
                Text(title).font(.system(size: 11, weight: .semibold))
            }
            .foregroundColor(on ? Color.primary : Color.secondary.opacity(0.8))
            .frame(maxWidth: .infinity)
            .contentShape(Rectangle())
        }.buttonStyle(.plain).focusable(false)
    }
}

struct RootView: View {
    @ObservedObject var m: HomeModel
    var onQuit: () -> Void

    var body: some View {
        let busy = m.busyDevices
        ZStack(alignment: .bottom) {
            VStack(spacing: 0) {
                HStack(spacing: 12) {
                    if m.households.count > 1 {
                        Menu {
                            ForEach(m.households) { h in
                                Button(h.name) { m.pickHousehold(h.id) }
                            }
                        } label: {
                            HStack(spacing: 6) {
                                Text(m.householdName).font(.system(size: 24, weight: .heavy))
                                Image(systemName: "chevron.down").font(.system(size: 13, weight: .bold))
                            }
                        }.menuStyle(.borderlessButton).fixedSize()
                    } else {
                        Text(m.token == nil ? "Мой дом" : m.householdName).font(.system(size: 24, weight: .heavy))
                    }
                    Spacer()
                    ZStack {
                        if m.loading { ProgressView().controlSize(.small) }
                    }
                    .frame(width: 20, height: 20)
                    if m.token != nil {
                        Button(action: { m.quickID = nil; m.detailID = nil; m.tab = m.tab == 3 ? 0 : 3 }) {
                            ZStack {
                                Circle().fill(m.tab == 3 ? purple : tileBG).frame(width: 34, height: 34)
                                Image(systemName: "chart.xyaxis.line").font(.system(size: 14, weight: .semibold))
                                    .foregroundColor(m.tab == 3 ? Color.white : Color.primary)
                            }
                            .frame(width: 34, height: 34)
                            .contentShape(Circle())
                        }.buttonStyle(.plain).focusable(false).help("Статистика: температура, влажность, воздух")
                        Button(action: { m.quickID = nil; m.detailID = nil; m.tab = m.tab == 2 ? 0 : 2 }) {
                            ZStack {
                                Circle().fill(m.tab == 2 ? purple : tileBG).frame(width: 34, height: 34)
                                Image(systemName: "gearshape.fill").font(.system(size: 16))
                                    .foregroundColor(m.tab == 2 ? Color.white : Color.primary)
                            }
                            .frame(width: 34, height: 34)
                            .contentShape(Circle())
                        }.buttonStyle(.plain).focusable(false).help("Настройки виджета")
                    } else {
                        Button(action: onQuit) {
                            ZStack {
                                Circle().fill(tileBG).frame(width: 34, height: 34)
                                Image(systemName: "xmark").font(.system(size: 13, weight: .bold)).foregroundColor(.secondary)
                            }
                        }.buttonStyle(.plain).focusable(false)
                    }
                }
                .padding(.horizontal, 18).padding(.top, 16).padding(.bottom, 10)
                if m.token != nil, m.showUpdateBanner, let t = m.latestTag {
                    UpdateBanner(m: m, tag: t).padding(.horizontal, 14).padding(.bottom, 8)
                }
                if m.token == nil {
                    LoginView(m: m)
                } else if m.rooms.isEmpty {
                    VStack(spacing: 10) {
                        Spacer()
                        if m.loading {
                            ProgressView()
                        } else {
                            Image(systemName: m.error == nil ? "house" : "wifi.exclamationmark").font(.system(size: 38)).foregroundColor(.secondary)
                            Text(m.error ?? "Устройств пока нет").font(.system(size: 13)).foregroundColor(.secondary)
                        }
                        Spacer()
                    }.frame(maxWidth: .infinity)
                } else {
                    if m.tab == 0 { DevicesPage(m: m) } else if m.tab == 1 { ScenariosPage(m: m) } else if m.tab == 3 { StatsPage(m: m) } else { SettingsView(m: m, onQuit: onQuit) }
                    Divider()
                    HStack {
                        TabButton(symbol: "house.fill", title: "Мой дом", on: m.tab == 0, action: { m.tab = 0 })
                        TabButton(symbol: "play.square.stack.fill", title: "Сценарии", on: m.tab == 1, action: { m.tab = 1 })
                        TabButton(symbol: "gearshape.fill", title: "Настройки", on: m.tab == 2, action: { m.tab = 2 })
                    }
                    .padding(.top, 8).padding(.bottom, 10)
                    .background(pageBG)
                }
            }
            if m.token != nil, m.detailID == nil, m.tab == 0, !busy.isEmpty {
                VStack(spacing: 8) {
                    ForEach(busy.prefix(2)) { d in
                        BusyBanner(d: d, m: m)
                    }
                }
                .padding(.horizontal, 14).padding(.bottom, 66)
            }
            if let id = m.detailID, let d = m.device(id) {
                DetailView(d: d, m: m)
                    .transition(.move(edge: .trailing))
                    .zIndex(5)
            }
            if let t = m.toast {
                Text(t).font(.system(size: 12, weight: .semibold)).foregroundColor(.white)
                    .multilineTextAlignment(.center).lineLimit(3)
                    .padding(.horizontal, 16).padding(.vertical, 9)
                    .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.black.opacity(0.82)))
                    .padding(.horizontal, 30)
                    .onTapGesture { m.toast = nil }
                    .padding(.bottom, 70)
            }
        }
        .frame(width: 500, height: panelHeight())
        .background(pageBG)
        .onExitCommand {
            if m.quickID != nil { m.quickID = nil }
            else if m.detailID != nil { m.closeDetail() }
            else if m.tab == 2 { m.tab = 0 }
        }
    }
}

/// «вышла новая версия» + что в ней нового (из описания релиза на GitHub)
struct UpdateBanner: View {
    @ObservedObject var m: HomeModel
    let tag: String

    var body: some View {
        let green = Color(red: 0.2, green: 0.7, blue: 0.4)
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "sparkles").foregroundColor(green)
                Text("Вышла версия " + tag).font(.system(size: 14, weight: .bold))
                Text("сейчас " + appVersion).font(.system(size: 11)).foregroundColor(.secondary)
                Spacer()
                Button(action: { m.dismissedTag = tag }) {
                    Image(systemName: "xmark").font(.system(size: 11, weight: .bold)).foregroundColor(.secondary)
                }.buttonStyle(.plain).focusable(false).help("Скрыть")
            }
            UpdateNotes(items: Array(m.latestNotes.prefix(5)))
            Button(action: {
                if let u = URL(string: m.latestURL ?? "https://github.com/Lenar111/yahome/releases/latest") { NSWorkspace.shared.open(u) }
            }) {
                Text("Открыть релиз на GitHub").font(.system(size: 12, weight: .semibold)).foregroundColor(.white)
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    .background(Capsule().fill(green))
            }.buttonStyle(.plain).focusable(false)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(green.opacity(0.12)))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(green.opacity(0.35), lineWidth: 1))
    }
}

struct UpdateNotes: View {
    let items: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, t in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text("•").font(.system(size: 12, weight: .bold)).foregroundColor(.secondary)
                    Text(t).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

// MARK: - Иконка в строке меню

/// цвет числа в строке меню: при нормальных значениях — обычный (nil), при отклонениях — предупреждающий цвет
func barTint(_ s: (String, String), dark: Bool = false) -> NSColor? {
    guard s.0.isEmpty else { return nil }
    let t = s.1
    let num = Double(t.replacingOccurrences(of: ",", with: ".").replacingOccurrences(of: "°", with: "").replacingOccurrences(of: "%", with: "").replacingOccurrences(of: "\u{2212}", with: "-"))
    guard let v = num else { return nil }
    func c(_ r: Double, _ g: Double, _ b: Double) -> NSColor {
        // на тёмной строке меню оттенки чуть светлее
        return dark ? NSColor(red: Swift.min(1, r + 0.18), green: Swift.min(1, g + 0.18), blue: Swift.min(1, b + 0.18), alpha: 1)
                    : NSColor(red: r, green: g, blue: b, alpha: 1)
    }
    if t.hasSuffix("°") {
        if v < 17 { return c(0.10, 0.35, 0.85) }       // холодно
        if v < 19 { return c(0.15, 0.50, 0.80) }       // прохладно
        if v <= 26 { return nil }                      // норма
        if v <= 28 { return c(0.85, 0.45, 0.0) }       // жарковато
        return c(0.82, 0.15, 0.12)                     // жарко
    }
    if t.hasSuffix("%") {
        if v < 30 { return c(0.82, 0.25, 0.10) }       // очень сухо
        if v < 35 { return c(0.85, 0.45, 0.0) }        // сухо
        if v <= 65 { return nil }                      // норма
        if v <= 70 { return c(0.15, 0.50, 0.80) }      // влажновато
        return c(0.10, 0.30, 0.80)                     // сыро
    }
    return nil
}

/// получает «курсор зашёл / вышел» от кнопки в строке меню
final class HoverTarget: NSResponder {
    var enter: (() -> Void)?
    var exit: (() -> Void)?

    override func mouseEntered(with event: NSEvent) { enter?() }
    override func mouseExited(with event: NSEvent) { exit?() }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var item: NSStatusItem!
    let pop = NSPopover()
    let model = HomeModel()
    let hoverTarget = HoverTarget()
    var animTimer: Timer?
    var phase = 0
    var hoverWork: DispatchWorkItem?
    var watch: Timer?
    var openedByHover = false
    var openedAt = Date.distantPast
    var engaged = false
    var outSince: Date?

    func applicationDidFinishLaunching(_ n: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.imagePosition = .imageLeft
        if let b = item.button {
            b.target = self
            b.action = #selector(toggle(_:))
            b.sendAction(on: [.leftMouseUp])
            hoverTarget.enter = { [weak self] in self?.hoverEnter() }
            hoverTarget.exit = { [weak self] in self?.hoverWork?.cancel() }
            b.addTrackingArea(NSTrackingArea(rect: .zero, options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect],
                                             owner: hoverTarget, userInfo: nil))
        }
        render()
        pop.behavior = .transient
        pop.animates = false
        pop.contentSize = NSSize(width: 500, height: panelHeight())
        let root = RootView(m: model, onQuit: { NSApp.terminate(nil) })
        pop.contentViewController = NSHostingController(rootView: root)
        model.onStatus = { [weak self] in self?.statusChanged() }
        NSEvent.addLocalMonitorForEvents(matching: .scrollWheel) { [weak self] e in
            guard let s = self, s.pop.isShown, s.model.tab == 0, s.model.detailID == nil else { return e }
            return s.model.scrollTile(e) ? nil : e
        }
        NotificationCenter.default.addObserver(forName: NSPopover.didCloseNotification, object: pop, queue: .main) { [weak self] _ in
            self?.watch?.invalidate()
            self?.model.closed()
        }
        if model.token != nil { model.refresh() }
        model.autoCheckUpdateIfNeeded()
        Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in self?.model.autoCheckUpdateIfNeeded() }
    }

    func statusChanged() {
        let busy = model.barBusy && !model.busyDevices.isEmpty
        if !busy {
            animTimer?.invalidate()
            animTimer = nil
        } else if animTimer == nil {
            animTimer = Timer.scheduledTimer(withTimeInterval: 0.6, repeats: true) { [weak self] _ in
                self?.phase += 1
                self?.render()
            }
        }
        render()
    }

    func render() {
        let segs = model.barSegments(phase)
        let font = NSFont.menuBarFont(ofSize: 0)
        let dark = item.button?.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        let neutral = dark ? NSColor.white : NSColor.black
        let upd = model.showUpdateBanner
        let anyTint = segs.contains { barTint($0, dark: dark) != nil }
        let cfg = NSImage.SymbolConfiguration(pointSize: 13.5, weight: .regular)
            .applying(NSImage.SymbolConfiguration(paletteColors: [neutral]))
        var parts: [(NSImage?, NSAttributedString)] = []
        var width: CGFloat = 0
        for (i, s) in segs.enumerated() {
            let tint = barTint(s, dark: dark)
            let attrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.monospacedDigitSystemFont(ofSize: font.pointSize - 1, weight: tint == nil ? .medium : .semibold),
                .foregroundColor: (anyTint || upd) ? (tint ?? neutral) : NSColor.black]
            var sym: NSImage? = nil
            if !s.0.isEmpty {
                sym = (NSImage(systemSymbolName: s.0, accessibilityDescription: nil)
                    ?? NSImage(systemSymbolName: "house", accessibilityDescription: nil))?.withSymbolConfiguration(cfg)
            }
            let str = NSAttributedString(string: s.1, attributes: attrs)
            parts.append((sym, str))
            width += (sym?.size.width ?? 0)
            if !s.1.isEmpty { width += (sym == nil ? 0 : 3) + ceil(str.size().width) }
            if i < segs.count - 1 { width += 10 }
        }
        let h: CGFloat = 18
        let dotW: CGFloat = upd ? 5 : 0
        let img = NSImage(size: NSSize(width: Swift.max(16, ceil(width)) + dotW, height: h), flipped: false) { _ in
            var x: CGFloat = 0
            for (i, p) in parts.enumerated() {
                if let sym = p.0 {
                    let sz = sym.size
                    sym.draw(in: NSRect(x: x, y: (h - sz.height) / 2, width: sz.width, height: sz.height))
                    x += sz.width
                }
                if p.1.length > 0 {
                    if p.0 != nil { x += 3 }
                    let ts = p.1.size()
                    p.1.draw(at: NSPoint(x: x, y: (h - ts.height) / 2 + 0.5))
                    x += ceil(ts.width)
                }
                if i < parts.count - 1 { x += 10 }
            }
            if upd {
                NSColor.systemRed.setFill()
                NSBezierPath(ovalIn: NSRect(x: x + 0.5, y: h - 8, width: 6, height: 6)).fill()
            }
            return true
        }
        img.isTemplate = !(anyTint || upd)
        item.button?.image = img
        item.button?.title = ""
        if let d = model.busyDevices.first { item.button?.toolTip = d.name + ": " + (d.statusLine ?? "работает") }
        else { item.button?.toolTip = "Мой дом" }
    }

    func hoverEnter() {
        guard model.hoverOpen, !pop.isShown else { return }
        hoverWork?.cancel()
        let w = DispatchWorkItem { [weak self] in self?.show(byHover: true) }
        hoverWork = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25, execute: w)
    }

    func show(byHover: Bool) {
        guard let b = item.button, !pop.isShown else { return }
        NSApp.activate(ignoringOtherApps: true)
        pop.show(relativeTo: b.bounds, of: b, preferredEdge: .minY)
        pop.contentViewController?.view.window?.makeKey()
        model.mainWindow = pop.contentViewController?.view.window
        model.opened()
        openedByHover = byHover
        openedAt = Date()
        engaged = !byHover
        outSince = nil
        watch?.invalidate()
        if model.hoverOpen {
            watch = Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { [weak self] _ in self?.checkHover() }
        }
    }

    /// курсор ушёл с окна виджета (и с его всплывающих панелей) — окно само закрывается
    func checkHover() {
        guard pop.isShown else { watch?.invalidate(); return }
        // во время входа или ввода текста не закрываем
        if model.token == nil || !model.hoverOpen { outSince = nil; return }
        let p = NSEvent.mouseLocation
        var inside = false
        for w in NSApp.windows where w.isVisible {
            if w.frame.insetBy(dx: -12, dy: -12).contains(p) { inside = true; break }
        }
        if inside || !model.draft.isEmpty {
            outSince = nil
            return
        }
        if let s = outSince {
            if Date().timeIntervalSince(s) > 0.6 { pop.performClose(nil) }
        } else {
            outSince = Date()
        }
    }

    @objc func toggle(_ sender: Any?) {
        hoverWork?.cancel()
        if pop.isShown {
            // щелчок сразу после раскрытия наведением — не закрываем, а «закрепляем»
            if openedByHover && Date().timeIntervalSince(openedAt) < 1.5 {
                engaged = true
                return
            }
            pop.performClose(nil)
            return
        }
        show(byHover: false)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
