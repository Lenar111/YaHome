// Необязательные картинки устройств.
//
// По умолчанию словарь пуст, и для каждого устройства рисуется векторная иконка
// (SF Symbols в цвете категории) — см. DevImage в YaHome.swift.
//
// Чтобы показывать свои картинки, добавьте PNG в base64 под ключами, которые возвращает
// Dev.iconKey (например "kettle", "ac", "tv", "bulb", "station", "vacuum", "purifier", "humidifier",
// "strip", "switch2", "lamp_white", "lamp_pink", "lamp_ambi", "ir", "music", "lite", "mini",
// "street_gray", "street_black"). Используйте только ту графику, на которую у вас есть права.
import Cocoa

enum Icons {
    static let iconData: [String: String] = [:]
}
